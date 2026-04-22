# threat_context.py
# Nmap Recon Analyzer — Threat Context Module
#
# This module takes parsed service data and enriches it with real-world
# threat intelligence: what attackers typically do when they find each
# service exposed, whether a host looks like a high-value target, and
# whether dangerous service combinations are present.
#
# No external libraries required — pure Python 3.

# ---------------------------------------------------------------------------
# THREAT KNOWLEDGE BASE
# ---------------------------------------------------------------------------
# Maps a normalised service name to a human-readable threat description.
THREAT_MAP = {
    # Remote access
    "ssh":            "Brute-force attacks — automated tools (Hydra, Medusa) target SSH "
                      "to gain shell access; compromised keys enable silent persistence.",
    "telnet":         "Cleartext credential interception — telnet transmits usernames and "
                      "passwords in plaintext, allowing trivial credential theft via network "
                      "sniffing. No encryption, no integrity protection.",
    "rdp":            "Remote access compromise — exposed RDP is a top ransomware entry point; "
                      "credential stuffing, BlueKeep (CVE-2019-0708), and DejaBlue exploits "
                      "allow unauthenticated RCE on unpatched Windows systems.",
    "vnc":            "Unauthenticated desktop takeover — VNC frequently ships with no password "
                      "or a weak single password. Cleartext transmission exposes sessions to "
                      "interception. Null-auth check is trivial to automate.",

    # File transfer
    "ftp":            "Unauthorized file access — FTP commonly allows anonymous login; "
                      "credentials travel in cleartext, enabling theft or malware staging "
                      "in the web root. vsftpd 2.3.4 backdoor (CVE-2011-1137) is still found.",
    "tftp":           "Unauthenticated file retrieval — TFTP requires no authentication. "
                      "Attackers can retrieve network device configs, /etc/passwd, or stage "
                      "payloads. Frequently overlooked because it runs over UDP.",

    # File sharing
    "smb":            "Lateral movement / ransomware — EternalBlue (CVE-2017-0144) and "
                      "SMBGhost (CVE-2020-0796) enable unauthenticated RCE. SMB is the "
                      "primary propagation vector for WannaCry, NotPetya, and most ransomware.",
    "netbios-ssn":    "Network reconnaissance and SMB relay — NetBIOS exposes host and "
                      "workgroup names, facilitates NTLM relay attacks, and pairs with SMB "
                      "vulnerabilities for lateral movement.",
    "nfs":            "Unauthenticated data exfiltration — misconfigured NFS exports with "
                      "wildcard permissions allow any host to mount and read/write sensitive "
                      "filesystem data without credentials.",

    # Web
    "http":           "Web application attacks — SQL injection, XSS, directory traversal, "
                      "and CMS exploitation are all possible against unencrypted HTTP. "
                      "Credentials submitted over HTTP are trivially intercepted.",
    "https":          "Web application attacks — same risks as HTTP plus TLS misconfiguration "
                      "threats: Heartbleed (CVE-2014-0160), POODLE, weak cipher suites, "
                      "and expired or self-signed certificates.",
    "http-proxy":     "Open proxy abuse — an unauthenticated proxy allows attackers to "
                      "pivot through the host to reach internal networks, bypass egress "
                      "filtering, or use the proxy as a C2 relay.",

    # Databases
    "mysql":          "Direct database access — MySQL often ships with an anonymous user "
                      "or empty root password. Port 3306 exposed to the internet risks full "
                      "data exfiltration and potential OS-level RCE via UDF injection.",
    "postgresql":     "Command execution via COPY — authenticated PostgreSQL sessions can "
                      "execute OS commands via COPY TO/FROM PROGRAM (CVE-2019-9193). "
                      "Exposed instances risk full database dump and server compromise.",
    "mssql":          "xp_cmdshell OS execution — MSSQL's built-in stored procedure enables "
                      "direct OS command execution from SQL. Exposed instances are a common "
                      "lateral-movement target in Windows environments.",
    "redis":          "Unauthenticated data access and persistence — Redis runs without auth "
                      "by default. CONFIG SET allows writing arbitrary files, enabling SSH "
                      "key injection, cron persistence, and Lua RCE (CVE-2022-0543).",
    "mongodb":        "Unauthenticated database exposure — MongoDB shipped without auth "
                      "enabled by default until 3.x; billions of records have been breached "
                      "from exposed instances. Ransomware bots actively scan port 27017.",
    "elasticsearch":  "Unauthenticated index access — Elasticsearch exposes all data over "
                      "HTTP with no auth by default. Dynamic scripting in older versions "
                      "enables RCE (Groovy sandbox escape, CVE-2015-1427).",

    # Mail
    "smtp":           "Open relay and user enumeration — an open SMTP relay enables spam "
                      "and phishing origination. VRFY/EXPN commands leak valid usernames "
                      "for subsequent credential attacks.",
    "pop3":           "Cleartext credential exposure — POP3 transmits passwords in plaintext "
                      "on port 110. Susceptible to credential interception and brute-force.",
    "imap":           "Cleartext credential exposure — IMAP on port 143 sends credentials "
                      "in plaintext. Compromised mailboxes expose sensitive communications "
                      "and can be used for internal phishing.",

    # Infrastructure
    "domain":         "DNS zone transfer and cache poisoning — misconfigured DNS servers "
                      "allow full zone transfers, exposing all internal host records. "
                      "SIGRed (CVE-2020-1350) enables unauthenticated RCE on Windows DNS.",
    "snmp":           "Infrastructure reconnaissance — default SNMP community strings "
                      "(public/private) expose full device configuration, interface lists, "
                      "running processes, and ARP tables. SNMPv1/v2 have no encryption.",
    "ldap":           "Active Directory enumeration — anonymous LDAP binds expose all "
                      "users, groups, computers, and OUs. This data feeds BloodHound "
                      "attack path analysis and Kerberoasting attacks.",
    "ldaps":          "Active Directory enumeration over TLS — encrypted LDAP still exposes "
                      "the full directory to authenticated or anonymous queries if bind "
                      "controls are not enforced.",
    "msrpc":          "RPC endpoint enumeration and exploitation — port 135 exposes all "
                      "registered RPC services. DCOM RPC buffer overflow (CVE-2003-0352, "
                      "Blaster worm) targeted this vector. Anonymous RPC sessions leak "
                      "domain user and group information.",
    "ntp":            "DDoS amplification — the NTP monlist command (CVE-2013-5211) "
                      "returns up to 600 client addresses per request, enabling significant "
                      "bandwidth amplification attacks against third-party targets.",
}

# How many HIGH-risk services must be present before we call the host a
# high-value target and raise the alert level.
HIGH_VALUE_THRESHOLD = 3

# ---------------------------------------------------------------------------
# DANGEROUS COMBINATION PATTERNS
# ---------------------------------------------------------------------------
# Each entry is (frozenset_of_services, warning_message).
# A flag is added to every insight on the host when the full pattern matches.
DANGEROUS_COMBOS = [
    (
        frozenset({"smb", "rdp"}),
        "COMBO: SMB + RDP present — classic ransomware staging environment.",
    ),
    (
        frozenset({"ftp", "http"}),
        "COMBO: FTP + HTTP present — file upload via FTP may expose web root.",
    ),
    (
        frozenset({"ssh", "ftp"}),
        "COMBO: SSH + FTP present — dual remote-access paths increase attack surface.",
    ),
    (
        frozenset({"http", "smb"}),
        "COMBO: HTTP + SMB present — potential pivot from web compromise to internal shares.",
    ),
]

# ---------------------------------------------------------------------------
# CORE FUNCTION — generate_threat_insights
# ---------------------------------------------------------------------------
def generate_threat_insights(services):
    """
    Analyse a list of detected services and produce actionable threat insights.

    Parameters
    ----------
    services : list[dict]
        Each dict must contain:
          - "port"    (int) : the open port number
          - "service" (str) : normalised service name, e.g. "ssh", "rdp"
          - "risk"    (str) : "HIGH", "MEDIUM", or "LOW"

    Returns
    -------
    insights : list[dict]
        One insight dict per service that has a known threat entry.
        Each dict contains:
          - "port"    : original port number
          - "service" : service name
          - "risk"    : original risk level
          - "threat"  : threat description from THREAT_MAP
          - "flags"   : list of special warning strings (may be empty)

    high_value_target : bool
        True when the host has 3 or more HIGH-risk services.
    """
    insights        = []       # Collects one insight per matched service
    high_risk_count = 0        # Counts services rated HIGH
    found_services  = set()    # Tracks which service names are present (for pattern detection)

    for entry in services:
        port    = entry.get("port")
        service = entry.get("service", "").lower().strip()
        risk    = entry.get("risk", "").upper().strip()

        # Keep a running set of all service names — used for pattern detection later
        found_services.add(service)

        # Count how many services are rated HIGH risk
        if risk == "HIGH":
            high_risk_count += 1

        # Only build an insight if we have threat intel for this service
        threat_description = THREAT_MAP.get(service)
        if not threat_description:
            # Unknown / unclassified service — skip
            continue

        insight = {
            "port":    port,
            "service": service,
            "risk":    risk,
            "threat":  threat_description,
            "flags":   [],          # populated in the second pass below
        }
        insights.append(insight)

    # -----------------------------------------------------------------------
    # SECOND PASS — attach combination flags to every relevant insight
    # -----------------------------------------------------------------------
    # Collect all combo warning strings that apply to this host.
    active_combo_flags = []
    for required_services, warning in DANGEROUS_COMBOS:
        if required_services.issubset(found_services):
            active_combo_flags.append(warning)

    # Stamp every insight with the host-level combo flags.
    for insight in insights:
        insight["flags"].extend(active_combo_flags)

    # -----------------------------------------------------------------------
    # HIGH-VALUE TARGET DETERMINATION
    # -----------------------------------------------------------------------
    high_value_target = high_risk_count >= HIGH_VALUE_THRESHOLD

    return insights, high_value_target


# ---------------------------------------------------------------------------
# IP ENRICHMENT — analyze_ip
# ---------------------------------------------------------------------------
import urllib.request
import urllib.error
import json as _json
import socket

# Countries flagged as elevated-risk sources in public threat intel feeds.
_HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "BY", "SY"}

def analyze_ip(ip: str) -> dict:
    """
    Enrich a single IP address with geolocation and threat signals.

    Uses ip-api.com (free, no API key, built-in urllib only).
    Returns a dict with four keys:
      - ip_info   : basic identity (hostname, org, ISP, AS)
      - geo_info  : location (country, region, city, lat/lon, timezone)
      - signals   : list of human-readable threat indicators
      - risk      : "HIGH", "MEDIUM", or "LOW"
    """
    # ------------------------------------------------------------------
    # Resolve hostname (best-effort — never fail the whole pipeline)
    # ------------------------------------------------------------------
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None

    # ------------------------------------------------------------------
    # Geo / ASN lookup via ip-api.com
    # ------------------------------------------------------------------
    fields = (
        "status,message,country,countryCode,regionName,city,"
        "lat,lon,timezone,isp,org,as,hosting,proxy,mobile"
    )
    url = f"http://ip-api.com/json/{ip}?fields={fields}"

    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = _json.loads(resp.read().decode())
    except Exception as exc:
        # Network unavailable or private IP — return a safe stub
        return {
            "ip_info":  {"ip": ip, "hostname": hostname, "org": None, "isp": None, "asn": None},
            "geo_info":  {"country": None, "country_code": None, "region": None,
                          "city": None, "lat": None, "lon": None, "timezone": None},
            "signals":  [f"IP lookup unavailable: {exc}"],
            "risk":     "UNKNOWN",
        }

    if data.get("status") != "success":
        return {
            "ip_info":  {"ip": ip, "hostname": hostname, "org": None, "isp": None, "asn": None},
            "geo_info":  {"country": None, "country_code": None, "region": None,
                          "city": None, "lat": None, "lon": None, "timezone": None},
            "signals":  [f"IP lookup failed: {data.get('message', 'unknown error')}"],
            "risk":     "UNKNOWN",
        }

    # ------------------------------------------------------------------
    # Build structured output
    # ------------------------------------------------------------------
    ip_info = {
        "ip":       ip,
        "hostname": hostname,
        "org":      data.get("org"),
        "isp":      data.get("isp"),
        "asn":      data.get("as"),
    }

    geo_info = {
        "country":      data.get("country"),
        "country_code": data.get("countryCode"),
        "region":       data.get("regionName"),
        "city":         data.get("city"),
        "lat":          data.get("lat"),
        "lon":          data.get("lon"),
        "timezone":     data.get("timezone"),
    }

    # ------------------------------------------------------------------
    # Generate threat signals
    # ------------------------------------------------------------------
    signals = []

    if data.get("hosting"):
        signals.append("IP is hosted in a commercial data center / cloud provider.")
    if data.get("proxy"):
        signals.append("IP identified as proxy, VPN, or Tor exit node.")
    if data.get("mobile"):
        signals.append("IP belongs to a mobile / cellular carrier.")
    if data.get("countryCode") in _HIGH_RISK_COUNTRIES:
        signals.append(
            f"IP originates from {data.get('country')} — elevated-risk country "
            f"per public threat intel feeds."
        )
    if not signals:
        signals.append("No automated threat signals detected for this IP.")

    # ------------------------------------------------------------------
    # Derive overall IP-level risk
    # ------------------------------------------------------------------
    if data.get("proxy"):
        risk = "HIGH"
    elif data.get("hosting") or data.get("countryCode") in _HIGH_RISK_COUNTRIES:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "ip_info":  ip_info,
        "geo_info": geo_info,
        "signals":  signals,
        "risk":     risk,
    }


# ---------------------------------------------------------------------------
# OPTIONAL HELPER — pretty_print_insights
# ---------------------------------------------------------------------------
def pretty_print_insights(insights, high_value_target):
    """Print insights to stdout in a readable report format."""
    if not insights:
        print("[*] No known-threat services detected.")
        return

    print("=" * 60)
    print("  THREAT CONTEXT REPORT")
    if high_value_target:
        print("  !! HIGH-VALUE TARGET — multiple critical services exposed !!")
    print("=" * 60)

    for i in insights:
        print(f"\n[Port {i['port']}]  {i['service'].upper()}  —  Risk: {i['risk']}")
        print(f"  Threat : {i['threat']}")
        for flag in i["flags"]:
            print(f"  FLAG   : {flag}")

    print("\n" + "=" * 60)


# ---------------------------------------------------------------------------
# QUICK SMOKE-TEST  (python threat_context.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sample_services = [
        {"port": 22,  "service": "ssh",  "risk": "HIGH"},
        {"port": 445, "service": "smb",  "risk": "HIGH"},
        {"port": 3389,"service": "rdp",  "risk": "HIGH"},
        {"port": 80,  "service": "http", "risk": "MEDIUM"},
        {"port": 9999,"service": "unknown_daemon", "risk": "LOW"},
    ]

    insights, hvt = generate_threat_insights(sample_services)
    pretty_print_insights(insights, hvt)

