# service_intelligence.py
# Part of: nmap-recon-analyzer
#
# Unified service knowledge base.
# Replaces classifier.py + enum_suggestions.py with a single, structured source
# of truth for every service the pipeline may encounter.
#
# Each record contains:
#   category           — broad service class (Remote Access, Database, etc.)
#   subcategory        — specific protocol type
#   protocol_cleartext — True when credentials travel in plaintext
#   anonymous_risk     — True when unauthenticated / guest access is common
#   attack_phases      — MITRE ATT&CK-aligned phases this service can enable
#   cve_prone          — True when the service has a notable CVE history
#   notable_cves       — key CVEs a SOC analyst should check for
#   enumeration        — risk-gated commands keyed Low / Medium / High / Critical
#                        (cumulative: Critical includes all lower tiers)
#   hardening_checks   — configuration items to verify during remediation
#
# Public API
# ----------
# analyze(service, port, risk_label)  → full intelligence dict
# classify(service, port)             → category string  (pipeline compat)
# enum_strings(service, port, risk)   → list[str] commands (formatter compat)

from __future__ import annotations

# ---------------------------------------------------------------------------
# Risk tier ordering — used for cumulative enumeration gating
# ---------------------------------------------------------------------------
_TIERS = ["Low", "Medium", "High", "Critical"]


def _gate(enum_map: dict, risk_label: str) -> list[dict]:
    """
    Return all enumeration commands up to and including risk_label.
    An 'Informational' or unknown label falls back to Low-tier only.
    """
    effective = risk_label if risk_label in _TIERS else "Low"
    cutoff    = _TIERS.index(effective)
    commands: list[dict] = []
    for tier in _TIERS[: cutoff + 1]:
        commands.extend(enum_map.get(tier, []))
    return commands


# ---------------------------------------------------------------------------
# Port → service name fallback map
# Used when the scanner reports a bare port with no service name.
# ---------------------------------------------------------------------------
_PORT_MAP: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "domain",
    69:    "tftp",
    80:    "http",
    88:    "kerberos",
    110:   "pop3",
    111:   "msrpc",
    135:   "msrpc",
    139:   "netbios-ssn",
    143:   "imap",
    161:   "snmp",
    389:   "ldap",
    443:   "https",
    445:   "smb",
    465:   "smtp",
    587:   "smtp",
    636:   "ldaps",
    993:   "imap",
    995:   "pop3",
    1433:  "mssql",
    2049:  "nfs",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http",
    8443:  "https",
    9200:  "elasticsearch",
    27017: "mongodb",
}

# ---------------------------------------------------------------------------
# Service knowledge base
# ---------------------------------------------------------------------------
_KB: dict[str, dict] = {

    # -----------------------------------------------------------------------
    # REMOTE ACCESS
    # -----------------------------------------------------------------------
    "ssh": {
        "category":           "Remote Access",
        "subcategory":        "Encrypted Shell",
        "protocol_cleartext": False,
        "anonymous_risk":     False,
        "attack_phases":      ["Initial Access", "Lateral Movement", "Persistence"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2016-10009 — OpenSSH < 7.4 privilege escalation",
            "CVE-2018-10933 — libssh authentication bypass",
            "CVE-2023-38408 — OpenSSH agent remote code execution",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm SSH version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script ssh-auth-methods,ssh-hostkey {target}",
                 "purpose": "Enumerate accepted auth methods and host key fingerprint"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ssh2-enum-algos {target}",
                 "purpose": "List supported ciphers and MACs — identify weak algorithms"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt ssh://{target}:{port} -t 4",
                 "purpose": "Credential brute-force (authorised testing only)"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ssh-brute {target}",
                 "purpose": "NSE-based SSH credential brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/ssh/ssh_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit SSH login scanner with credential list"},
                {"tool": "msf",   "command": "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}",
                 "purpose": "Enumerate valid usernames via timing side-channel"},
            ],
        },
        "hardening_checks": [
            "Set PasswordAuthentication no in /etc/ssh/sshd_config",
            "Enforce Protocol 2 only",
            "Set MaxAuthTries 3 or lower",
            "Restrict access with AllowUsers / AllowGroups",
            "Disable root login (PermitRootLogin no)",
            "Verify OpenSSH ≥ 8.0 to mitigate known CVEs",
            "Consider key-based authentication exclusively",
        ],
    },

    "telnet": {
        "category":           "Remote Access",
        "subcategory":        "Cleartext Shell",
        "protocol_cleartext": True,
        "anonymous_risk":     False,
        "attack_phases":      ["Initial Access", "Credential Theft", "Lateral Movement"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2011-4862 — FreeBSD telnetd remote code execution",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm telnet service and banner"},
                {"tool": "nmap",  "command": "nmap -p {port} --script telnet-ntlm-info {target}",
                 "purpose": "Retrieve NTLM info from telnet banner"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script telnet-encryption {target}",
                 "purpose": "Check if telnet encryption is in use"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt telnet://{target}:{port}",
                 "purpose": "Credential brute-force over cleartext telnet"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/telnet/telnet_login; set RHOSTS {target}",
                 "purpose": "Metasploit telnet login scanner"},
            ],
        },
        "hardening_checks": [
            "Disable telnet entirely — replace with SSH",
            "If telnet cannot be removed, restrict via firewall to management VLAN only",
            "Audit all devices still running telnet for migration timeline",
        ],
    },

    "rdp": {
        "category":           "Remote Access",
        "subcategory":        "Remote Desktop",
        "protocol_cleartext": False,
        "anonymous_risk":     False,
        "attack_phases":      ["Initial Access", "Lateral Movement", "Defense Evasion", "Persistence"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2019-0708 — BlueKeep unauthenticated RCE (Windows 7/2008)",
            "CVE-2019-1181/1182 — DejaBlue RCE (Windows 8+/2019)",
            "CVE-2012-0002 — MS12-020 denial of service",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm RDP version and OS fingerprint"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script rdp-enum-encryption {target}",
                 "purpose": "Check RDP encryption level — flag NLA not enforced"},
                {"tool": "nmap",  "command": "nmap -p {port} --script rdp-vuln-ms12-020 {target}",
                 "purpose": "Test MS12-020 denial of service vulnerability"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p {port} --script rdp-enum-encryption,rdp-vuln-ms12-020 {target}",
                 "purpose": "Full RDP vulnerability sweep"},
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt rdp://{target}:{port}",
                 "purpose": "RDP credential brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {target}",
                 "purpose": "BlueKeep RCE check (CVE-2019-0708) — Windows 7/2008 only"},
                {"tool": "msf",   "command": "use auxiliary/scanner/rdp/rdp_scanner; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Confirm RDP is accessible and enumerate settings"},
            ],
        },
        "hardening_checks": [
            "Enforce Network Level Authentication (NLA)",
            "Restrict RDP access to VPN or jump host — never expose directly to internet",
            "Enable account lockout policy (3-5 failed attempts)",
            "Apply MS patch for BlueKeep (KB4499175) and DejaBlue",
            "Disable RDP if not required",
            "Enable RDP logging and alert on off-hours access",
        ],
    },

    "vnc": {
        "category":           "Remote Access",
        "subcategory":        "Remote Desktop (Lightweight)",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Lateral Movement"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2006-2369 — RealVNC authentication bypass",
            "CVE-2019-15694 — LibVNC heap overflow",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm VNC version and implementation"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script vnc-info,vnc-brute {target}",
                 "purpose": "Enumerate VNC security type and attempt null auth"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -P passwords.txt vnc://{target}:{port}",
                 "purpose": "VNC password brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/vnc/vnc_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit VNC login scanner"},
                {"tool": "msf",   "command": "use auxiliary/scanner/vnc/vnc_none_auth; set RHOSTS {target}",
                 "purpose": "Check for VNC null authentication (no password required)"},
            ],
        },
        "hardening_checks": [
            "Require strong VNC password (minimum 8 characters)",
            "Disable VNC if RDP or SSH is available — VNC sends cleartext",
            "Restrict VNC to localhost and use SSH tunnel",
            "Apply all vendor security patches",
        ],
    },

    # -----------------------------------------------------------------------
    # FILE TRANSFER
    # -----------------------------------------------------------------------
    "ftp": {
        "category":           "File Transfer",
        "subcategory":        "Cleartext File Transfer",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Exfiltration", "Command and Control"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2010-4221 — ProFTPD remote code execution",
            "CVE-2011-1137 — vsftpd 2.3.4 backdoor",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm FTP version and implementation"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ftp-anon {target}",
                 "purpose": "Test for anonymous FTP login"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script ftp-syst,ftp-bounce,ftp-anon {target}",
                 "purpose": "Full FTP enumeration — system type, bounce, anonymous access"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt ftp://{target}:{port}",
                 "purpose": "FTP credential brute-force"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ftp-brute {target}",
                 "purpose": "NSE-based FTP brute force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/ftp/ftp_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit FTP login scanner"},
                {"tool": "msf",   "command": "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}",
                 "purpose": "vsftpd 2.3.4 backdoor check (CVE-2011-1137)"},
            ],
        },
        "hardening_checks": [
            "Disable anonymous FTP login",
            "Replace FTP with SFTP or FTPS",
            "Restrict FTP to specific IP ranges via firewall",
            "Enable FTP logging and monitor for large transfers",
            "Isolate FTP service in a DMZ with no internal network access",
        ],
    },

    "tftp": {
        "category":           "File Transfer",
        "subcategory":        "Unauthenticated File Transfer",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Exfiltration", "Collection"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sU -sV {target}",
                 "purpose": "Confirm TFTP service (UDP)"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} -sU --script tftp-enum {target}",
                 "purpose": "Enumerate accessible files via TFTP"},
            ],
            "High": [
                {"tool": "tftp",  "command": "tftp {target}; get /etc/passwd",
                 "purpose": "Attempt to retrieve sensitive files — no auth required"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {target}",
                 "purpose": "TFTP file enumeration via brute-force filenames"},
            ],
        },
        "hardening_checks": [
            "Disable TFTP if not required for network device bootstrapping",
            "Restrict TFTP to management VLAN only",
            "Ensure TFTP root directory contains no sensitive files",
        ],
    },

    # -----------------------------------------------------------------------
    # FILE SHARING
    # -----------------------------------------------------------------------
    "smb": {
        "category":           "File Sharing",
        "subcategory":        "Windows File Sharing",
        "protocol_cleartext": False,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Lateral Movement", "Collection", "Exfiltration"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2017-0144 — EternalBlue SMBv1 RCE (WannaCry / NotPetya)",
            "CVE-2020-0796 — SMBGhost SMBv3 RCE",
            "CVE-2021-1675  — PrintNightmare RCE via spooler",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm SMB version — flag SMBv1"},
                {"tool": "nmap",  "command": "nmap -p {port} --script smb-security-mode {target}",
                 "purpose": "Check SMB security mode — guest access, signing status"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script smb-enum-shares,smb-enum-users {target}",
                 "purpose": "Enumerate accessible shares and user accounts"},
                {"tool": "smbclient", "command": "smbclient -L //{target} -N",
                 "purpose": "List shares without authentication"},
                {"tool": "enum4linux", "command": "enum4linux -a {target}",
                 "purpose": "Full SMB enumeration — shares, users, groups, password policy"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p {port} --script smb-vuln-ms17-010 {target}",
                 "purpose": "EternalBlue vulnerability check (CVE-2017-0144)"},
                {"tool": "nmap",  "command": "nmap -p {port} --script smb-vuln-cve-2020-0796 {target}",
                 "purpose": "SMBGhost vulnerability check (CVE-2020-0796)"},
                {"tool": "crackmapexec", "command": "crackmapexec smb {target} -u users.txt -p passwords.txt",
                 "purpose": "SMB credential spray"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}",
                 "purpose": "EternalBlue RCE exploitation (CVE-2017-0144)"},
                {"tool": "msf",   "command": "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS {target}",
                 "purpose": "Confirm EternalBlue vulnerability before exploitation"},
            ],
        },
        "hardening_checks": [
            "Disable SMBv1 entirely (Set-SmbServerConfiguration -EnableSMB1Protocol $false)",
            "Enable SMB signing on all hosts",
            "Restrict SMB to internal networks — block port 445 at perimeter",
            "Apply MS17-010 patch (KB4012212) and SMBGhost patch (KB4551762)",
            "Audit SMB shares for anonymous / guest access",
            "Disable the print spooler service on non-print servers (PrintNightmare)",
        ],
    },

    "netbios-ssn": {
        "category":           "File Sharing",
        "subcategory":        "NetBIOS Session Service",
        "protocol_cleartext": False,
        "anonymous_risk":     True,
        "attack_phases":      ["Discovery", "Lateral Movement", "Collection"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2017-0144 — EternalBlue (also exploits port 139)",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm NetBIOS version"},
            ],
            "Medium": [
                {"tool": "enum4linux", "command": "enum4linux -n {target}",
                 "purpose": "Enumerate NetBIOS names and workgroup"},
                {"tool": "nbtscan",    "command": "nbtscan {target}",
                 "purpose": "NetBIOS name table scan"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p 139,445 --script smb-enum-shares,smb-enum-users {target}",
                 "purpose": "Full SMB/NetBIOS share and user enumeration"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/netbios/nbname; set RHOSTS {target}",
                 "purpose": "NetBIOS name service enumeration"},
            ],
        },
        "hardening_checks": [
            "Disable NetBIOS over TCP/IP where not required",
            "Block ports 137-139 at network perimeter",
            "Use DNS for name resolution instead of NetBIOS",
        ],
    },

    "nfs": {
        "category":           "File Sharing",
        "subcategory":        "Network File System",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Collection", "Exfiltration"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm NFS version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script nfs-ls,nfs-showmount {target}",
                 "purpose": "List NFS exports and their contents"},
                {"tool": "showmount", "command": "showmount -e {target}",
                 "purpose": "Show exported NFS file systems"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p {port} --script nfs-ls,nfs-statfs,nfs-showmount {target}",
                 "purpose": "Full NFS enumeration including disk statistics"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/nfs/nfsmount; set RHOSTS {target}",
                 "purpose": "Attempt to mount NFS exports without authentication"},
            ],
        },
        "hardening_checks": [
            "Restrict NFS exports to specific host IPs — never use wildcard (*)",
            "Use AUTH_GSS (Kerberos) instead of AUTH_SYS",
            "Mount exports read-only where write is not needed",
            "Block NFS ports (2049, 111) at network perimeter",
        ],
    },

    # -----------------------------------------------------------------------
    # WEB SERVICES
    # -----------------------------------------------------------------------
    "http": {
        "category":           "Web Service",
        "subcategory":        "Unencrypted Web",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Collection", "Execution"],
        "cve_prone":          True,
        "notable_cves": [
            "Application-specific CVEs — depends on CMS/framework version",
        ],
        "enumeration": {
            "Low": [
                {"tool": "curl",    "command": "curl -I http://{target}:{port}/",
                 "purpose": "Retrieve HTTP headers — server version, security headers"},
                {"tool": "whatweb", "command": "whatweb http://{target}:{port}",
                 "purpose": "Fingerprint web technology stack"},
            ],
            "Medium": [
                {"tool": "gobuster", "command": "gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt",
                 "purpose": "Directory and file enumeration"},
                {"tool": "nmap",     "command": "nmap -p {port} --script http-title,http-headers,http-methods {target}",
                 "purpose": "Enumerate HTTP title, headers, and allowed methods"},
            ],
            "High": [
                {"tool": "nikto",    "command": "nikto -h http://{target}:{port}",
                 "purpose": "Web vulnerability scan — misconfigs, outdated software, dangerous files"},
                {"tool": "nmap",     "command": "nmap -p {port} --script http-vuln-* {target}",
                 "purpose": "NSE HTTP vulnerability scripts"},
                {"tool": "gobuster", "command": "gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                 "purpose": "Deep directory brute-force with medium wordlist"},
            ],
            "Critical": [
                {"tool": "sqlmap",   "command": "sqlmap -u 'http://{target}:{port}/' --dbs --batch",
                 "purpose": "Automated SQL injection detection and exploitation"},
                {"tool": "msf",      "command": "use auxiliary/scanner/http/http_version; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "HTTP server version and vulnerability correlation"},
            ],
        },
        "hardening_checks": [
            "Redirect all HTTP to HTTPS — disable plain HTTP where possible",
            "Set security headers: Strict-Transport-Security, X-Frame-Options, Content-Security-Policy",
            "Remove server version from response headers (ServerTokens Prod)",
            "Disable directory listing",
            "Keep web framework and CMS fully patched",
            "Remove default pages, admin interfaces, and test files",
        ],
    },

    "https": {
        "category":           "Web Service",
        "subcategory":        "Encrypted Web",
        "protocol_cleartext": False,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Collection", "Execution"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2014-0160 — Heartbleed (OpenSSL)",
            "CVE-2016-2107 — POODLE / DROWN (weak TLS)",
            "Application-specific CVEs — depends on CMS/framework",
        ],
        "enumeration": {
            "Low": [
                {"tool": "curl",    "command": "curl -I https://{target}:{port}/",
                 "purpose": "Retrieve HTTPS headers and TLS certificate info"},
                {"tool": "nmap",    "command": "nmap -p {port} --script ssl-cert,ssl-enum-ciphers {target}",
                 "purpose": "Enumerate TLS certificate and supported cipher suites"},
            ],
            "Medium": [
                {"tool": "whatweb",  "command": "whatweb https://{target}:{port}",
                 "purpose": "Fingerprint web technology stack"},
                {"tool": "gobuster", "command": "gobuster dir -u https://{target}:{port} -w /usr/share/wordlists/dirb/common.txt -k",
                 "purpose": "Directory enumeration over HTTPS"},
                {"tool": "nmap",     "command": "nmap -p {port} --script http-title,http-headers,http-methods {target}",
                 "purpose": "Enumerate HTTP methods and response headers"},
            ],
            "High": [
                {"tool": "nikto",   "command": "nikto -h https://{target}:{port} -ssl",
                 "purpose": "Web vulnerability scan over HTTPS"},
                {"tool": "sslscan", "command": "sslscan {target}:{port}",
                 "purpose": "Full TLS configuration audit — weak ciphers, protocol versions"},
                {"tool": "testssl", "command": "testssl.sh {target}:{port}",
                 "purpose": "Comprehensive TLS/SSL vulnerability check"},
            ],
            "Critical": [
                {"tool": "nmap",  "command": "nmap -p {port} --script ssl-heartbleed {target}",
                 "purpose": "Heartbleed vulnerability check (CVE-2014-0160)"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ssl-poodle,ssl-drown {target}",
                 "purpose": "POODLE and DROWN vulnerability check"},
                {"tool": "sqlmap","command": "sqlmap -u 'https://{target}:{port}/' --dbs --batch",
                 "purpose": "SQL injection detection and exploitation"},
            ],
        },
        "hardening_checks": [
            "Disable TLS 1.0 and TLS 1.1 — enforce TLS 1.2+ only",
            "Disable weak cipher suites (RC4, DES, 3DES, NULL)",
            "Enable HSTS with includeSubDomains and preload",
            "Ensure certificate is not expired and uses SHA-256 or better",
            "Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options",
            "Keep OpenSSL and web server fully patched",
        ],
    },

    "http-proxy": {
        "category":           "Web Service",
        "subcategory":        "Open / Reverse Proxy",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Defense Evasion", "Command and Control"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "curl",  "command": "curl -x http://{target}:{port} http://example.com",
                 "purpose": "Test if proxy allows outbound connections (open proxy)"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script http-open-proxy {target}",
                 "purpose": "Detect open proxy — can be used to bypass network controls"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p {port} --script http-proxy-brute {target}",
                 "purpose": "Brute-force proxy authentication if required"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/http/squid_pivot_scanning; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Use proxy to pivot and scan internal network"},
            ],
        },
        "hardening_checks": [
            "Require authentication on all proxy services",
            "Block direct internet access through proxy from untrusted zones",
            "Log all proxy requests and alert on unusual destinations",
            "Disable CONNECT method unless required for HTTPS tunnelling",
        ],
    },

    # -----------------------------------------------------------------------
    # DATABASES
    # -----------------------------------------------------------------------
    "mysql": {
        "category":           "Database",
        "subcategory":        "Relational Database",
        "protocol_cleartext": False,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Collection", "Exfiltration"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2012-2122 — MySQL authentication bypass",
            "CVE-2016-6662 — MySQL remote code execution via config file",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm MySQL version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script mysql-info,mysql-empty-password {target}",
                 "purpose": "Check for empty root password and retrieve server info"},
                {"tool": "nmap",  "command": "nmap -p {port} --script mysql-databases {target}",
                 "purpose": "Enumerate accessible databases (may require creds)"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt mysql://{target}:{port}",
                 "purpose": "MySQL credential brute-force"},
                {"tool": "nmap",  "command": "nmap -p {port} --script mysql-vuln-cve2012-2122 {target}",
                 "purpose": "CVE-2012-2122 authentication bypass check"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/mysql/mysql_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit MySQL login scanner"},
                {"tool": "msf",   "command": "use exploit/multi/mysql/mysql_udf_payload; set RHOSTS {target}",
                 "purpose": "MySQL UDF code execution (requires privileged login)"},
            ],
        },
        "hardening_checks": [
            "Remove anonymous user accounts (DELETE FROM mysql.user WHERE User='')",
            "Set a strong root password",
            "Bind MySQL to localhost only (bind-address = 127.0.0.1)",
            "Remove the test database",
            "Restrict GRANT privileges — least privilege per application user",
            "Enable MySQL audit logging",
        ],
    },

    "postgresql": {
        "category":           "Database",
        "subcategory":        "Relational Database",
        "protocol_cleartext": False,
        "anonymous_risk":     False,
        "attack_phases":      ["Initial Access", "Collection", "Exfiltration", "Execution"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2019-9193 — PostgreSQL arbitrary command execution via COPY TO/FROM PROGRAM",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm PostgreSQL version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script pgsql-brute {target}",
                 "purpose": "NSE-based PostgreSQL brute-force"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt postgres://{target}:{port}",
                 "purpose": "PostgreSQL credential brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/postgres/postgres_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit PostgreSQL login scanner"},
                {"tool": "msf",   "command": "use exploit/multi/postgres/postgres_copy_from_program_cmd_exec; set RHOSTS {target}",
                 "purpose": "CVE-2019-9193 COPY FROM PROGRAM RCE"},
            ],
        },
        "hardening_checks": [
            "Bind PostgreSQL to localhost only (listen_addresses = 'localhost')",
            "Use pg_hba.conf to restrict client authentication by IP",
            "Apply principle of least privilege per database role",
            "Disable trust authentication — require md5 or scram-sha-256",
            "Keep PostgreSQL patched to latest minor version",
        ],
    },

    "mssql": {
        "category":           "Database",
        "subcategory":        "Microsoft SQL Server",
        "protocol_cleartext": False,
        "anonymous_risk":     False,
        "attack_phases":      ["Initial Access", "Lateral Movement", "Execution", "Exfiltration"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2000-0402 — MSSQL resolution service buffer overflow",
            "xp_cmdshell abuse — built-in stored procedure for OS command execution",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm MSSQL version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script ms-sql-info,ms-sql-config {target}",
                 "purpose": "Enumerate MSSQL server information and configuration"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ms-sql-empty-password {target}",
                 "purpose": "Check for empty SA password"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt mssql://{target}:{port}",
                 "purpose": "MSSQL credential brute-force"},
                {"tool": "nmap",  "command": "nmap -p {port} --script ms-sql-xp-cmdshell {target}",
                 "purpose": "Test if xp_cmdshell is enabled — OS command execution"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/mssql/mssql_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit MSSQL login scanner"},
                {"tool": "msf",   "command": "use exploit/windows/mssql/mssql_payload; set RHOSTS {target}",
                 "purpose": "MSSQL payload execution via xp_cmdshell"},
            ],
        },
        "hardening_checks": [
            "Disable xp_cmdshell (EXEC sp_configure 'xp_cmdshell', 0)",
            "Rename or disable the SA account",
            "Enable Windows Authentication over SQL Authentication where possible",
            "Block port 1433 at network perimeter — restrict to app servers only",
            "Enable SQL Server Audit for all login events",
            "Apply all Microsoft SQL Server Cumulative Updates",
        ],
    },

    "redis": {
        "category":           "Database",
        "subcategory":        "In-Memory Data Store",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Persistence", "Lateral Movement", "Exfiltration"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2022-0543 — Redis Lua sandbox escape (RCE)",
            "Redis CONFIG SET dir / dbfilename — write files to arbitrary paths without auth",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm Redis version"},
                {"tool": "redis-cli", "command": "redis-cli -h {target} -p {port} ping",
                 "purpose": "Test unauthenticated access — PONG response = no auth required"},
            ],
            "Medium": [
                {"tool": "redis-cli", "command": "redis-cli -h {target} -p {port} info",
                 "purpose": "Retrieve Redis server info, memory usage, and configuration"},
                {"tool": "redis-cli", "command": "redis-cli -h {target} -p {port} config get *",
                 "purpose": "Dump full Redis configuration — may expose paths and passwords"},
            ],
            "High": [
                {"tool": "redis-cli", "command": "redis-cli -h {target} -p {port} keys '*'",
                 "purpose": "List all stored keys — may contain sensitive application data"},
                {"tool": "nmap",      "command": "nmap -p {port} --script redis-info {target}",
                 "purpose": "NSE Redis info enumeration"},
            ],
            "Critical": [
                {"tool": "redis-cli", "command": "redis-cli -h {target} -p {port} config set dir /root/.ssh; config set dbfilename authorized_keys; set x 'ssh-rsa AAAA...'",
                 "purpose": "Unauthenticated SSH key injection via Redis CONFIG SET (PoC — authorised only)"},
                {"tool": "msf",       "command": "use exploit/linux/redis/redis_replication_cmd_exec; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Redis replication code execution"},
            ],
        },
        "hardening_checks": [
            "Enable requirepass in redis.conf — set a strong password",
            "Bind Redis to localhost only (bind 127.0.0.1)",
            "Rename or disable CONFIG, SLAVEOF, DEBUG commands",
            "Run Redis as a dedicated non-root user",
            "Enable TLS for Redis connections (Redis 6+)",
            "Block port 6379 at all network perimeters",
        ],
    },

    "mongodb": {
        "category":           "Database",
        "subcategory":        "NoSQL Document Store",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Collection", "Exfiltration"],
        "cve_prone":          False,
        "notable_cves":       [
            "Misconfiguration CVE: MongoDB exposed without auth is its own class of breach",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm MongoDB version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script mongodb-info {target}",
                 "purpose": "Retrieve MongoDB server info and build version"},
                {"tool": "mongo", "command": "mongo {target}:{port} --eval 'db.adminCommand({listDatabases:1})'",
                 "purpose": "List all databases — no auth check"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p {port} --script mongodb-databases {target}",
                 "purpose": "Enumerate accessible MongoDB databases"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/gather/mongodb_js_inject_collection_enum; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit MongoDB collection enumeration via JS injection"},
            ],
        },
        "hardening_checks": [
            "Enable MongoDB authentication (--auth flag)",
            "Bind MongoDB to localhost only (--bind_ip 127.0.0.1)",
            "Create dedicated users with least-privilege roles per database",
            "Enable TLS for all MongoDB connections",
            "Disable the HTTP status interface (--nohttpinterface)",
            "Block port 27017 at all network perimeters",
        ],
    },

    "elasticsearch": {
        "category":           "Database",
        "subcategory":        "Search and Analytics Engine",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Collection", "Exfiltration"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2014-3120 — Elasticsearch dynamic script RCE",
            "CVE-2015-1427 — Groovy sandbox escape RCE",
        ],
        "enumeration": {
            "Low": [
                {"tool": "curl",  "command": "curl http://{target}:{port}/",
                 "purpose": "Check if Elasticsearch responds without authentication"},
            ],
            "Medium": [
                {"tool": "curl",  "command": "curl http://{target}:{port}/_cat/indices?v",
                 "purpose": "List all indices — may contain sensitive application data"},
                {"tool": "curl",  "command": "curl http://{target}:{port}/_cluster/settings?pretty",
                 "purpose": "Retrieve cluster configuration and security settings"},
            ],
            "High": [
                {"tool": "curl",  "command": "curl http://{target}:{port}/_cat/nodes?v",
                 "purpose": "Enumerate all cluster nodes and their versions"},
                {"tool": "nmap",  "command": "nmap -p {port} --script http-elasticsearch {target}",
                 "purpose": "NSE Elasticsearch enumeration"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use exploit/multi/elasticsearch/search_groovy_script; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Elasticsearch Groovy script RCE (CVE-2015-1427)"},
            ],
        },
        "hardening_checks": [
            "Enable X-Pack security or equivalent authentication plugin",
            "Bind Elasticsearch to localhost or private network interface only",
            "Disable dynamic scripting unless required",
            "Block port 9200 and 9300 at all network perimeters",
            "Enable audit logging for all index and cluster operations",
        ],
    },

    # -----------------------------------------------------------------------
    # MAIL
    # -----------------------------------------------------------------------
    "smtp": {
        "category":           "Email Service",
        "subcategory":        "Mail Transfer Agent",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Initial Access", "Exfiltration", "Command and Control"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2019-15846 — Exim remote code execution (EHLO/HELO buffer overflow)",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm SMTP version and MTA software"},
                {"tool": "nmap",  "command": "nmap -p {port} --script smtp-open-relay {target}",
                 "purpose": "Test for open mail relay — allows spam/phishing origination"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script smtp-enum-users {target}",
                 "purpose": "Enumerate valid email users via VRFY/EXPN/RCPT TO"},
                {"tool": "smtp-user-enum", "command": "smtp-user-enum -M VRFY -U users.txt -t {target}",
                 "purpose": "Username enumeration via SMTP VRFY command"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt smtp://{target}:{port}",
                 "purpose": "SMTP AUTH credential brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/smtp/smtp_relay; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Confirm open relay vulnerability"},
            ],
        },
        "hardening_checks": [
            "Disable VRFY and EXPN commands to prevent user enumeration",
            "Require SMTP AUTH for all outbound mail",
            "Implement SPF, DKIM, and DMARC records",
            "Restrict relaying to authorised IP ranges only",
            "Enable TLS (STARTTLS) for all SMTP connections",
        ],
    },

    "pop3": {
        "category":           "Email Service",
        "subcategory":        "Mail Retrieval Protocol",
        "protocol_cleartext": True,
        "anonymous_risk":     False,
        "attack_phases":      ["Credential Theft", "Collection"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm POP3 version and implementation"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script pop3-capabilities {target}",
                 "purpose": "List POP3 server capabilities — check STLS support"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt pop3://{target}:{port}",
                 "purpose": "POP3 credential brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/pop3/pop3_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit POP3 login scanner"},
            ],
        },
        "hardening_checks": [
            "Migrate users to POP3S (port 995) or IMAPS",
            "Disable plain POP3 on port 110",
            "Implement account lockout after failed login attempts",
        ],
    },

    "imap": {
        "category":           "Email Service",
        "subcategory":        "Mail Access Protocol",
        "protocol_cleartext": True,
        "anonymous_risk":     False,
        "attack_phases":      ["Credential Theft", "Collection"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm IMAP version"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script imap-capabilities {target}",
                 "purpose": "Enumerate IMAP capabilities — check STARTTLS support"},
            ],
            "High": [
                {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt imap://{target}:{port}",
                 "purpose": "IMAP credential brute-force"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/imap/imap_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit IMAP login scanner"},
            ],
        },
        "hardening_checks": [
            "Migrate to IMAPS (port 993) — disable plain IMAP on port 143",
            "Require STARTTLS before authentication",
            "Implement account lockout policy",
        ],
    },

    # -----------------------------------------------------------------------
    # INFRASTRUCTURE
    # -----------------------------------------------------------------------
    "domain": {
        "category":           "Infrastructure",
        "subcategory":        "DNS Server",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Discovery", "Initial Access"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2020-1350 — SIGRed Windows DNS Server RCE",
            "CVE-2008-1447 — Kaminsky DNS cache poisoning",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm DNS software and version"},
                {"tool": "dig",   "command": "dig @{target} version.bind chaos txt",
                 "purpose": "Retrieve DNS server version via CHAOS class query"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script dns-zone-transfer {target}",
                 "purpose": "Attempt DNS zone transfer — exposes all DNS records if misconfigured"},
                {"tool": "dig",   "command": "dig axfr @{target} <domain>",
                 "purpose": "Manual zone transfer attempt"},
                {"tool": "dnsrecon", "command": "dnsrecon -d <domain> -n {target} -t axfr",
                 "purpose": "Full DNS recon including zone transfer attempt"},
            ],
            "High": [
                {"tool": "fierce","command": "fierce --dns-servers {target} --domain <domain>",
                 "purpose": "DNS brute-force subdomain and host enumeration"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/gather/dns_bruteforce; set RHOST {target}; set DOMAIN <domain>",
                 "purpose": "Metasploit DNS subdomain brute-force"},
            ],
        },
        "hardening_checks": [
            "Restrict zone transfers to authorised secondary DNS servers only",
            "Disable recursion on authoritative DNS servers",
            "Patch SIGRed vulnerability (KB4569509) on Windows DNS servers",
            "Enable DNSSEC to prevent cache poisoning",
            "Hide or remove CHAOS version.bind response",
        ],
    },

    "snmp": {
        "category":           "Infrastructure",
        "subcategory":        "Network Management",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Discovery", "Collection", "Initial Access"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2002-0013 — Multiple SNMP v1 implementations buffer overflow",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sU -sV {target}",
                 "purpose": "Confirm SNMP version (UDP scan required)"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} -sU --script snmp-info,snmp-sysdescr {target}",
                 "purpose": "Retrieve system description, OS, and uptime via SNMP"},
                {"tool": "onesixtyone", "command": "onesixtyone -c community_strings.txt {target}",
                 "purpose": "Brute-force SNMP community strings (default: public, private)"},
            ],
            "High": [
                {"tool": "snmpwalk", "command": "snmpwalk -v2c -c public {target}",
                 "purpose": "Full SNMP walk — enumerates entire MIB tree"},
                {"tool": "nmap",    "command": "nmap -p {port} -sU --script snmp-interfaces,snmp-netstat,snmp-processes {target}",
                 "purpose": "Enumerate network interfaces, connections, and running processes"},
            ],
            "Critical": [
                {"tool": "msf",  "command": "use auxiliary/scanner/snmp/snmp_login; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Brute-force SNMP community strings with Metasploit"},
                {"tool": "msf",  "command": "use auxiliary/scanner/snmp/snmp_enum; set RHOSTS {target}",
                 "purpose": "Full Metasploit SNMP enumeration — users, shares, services"},
            ],
        },
        "hardening_checks": [
            "Upgrade to SNMPv3 with authentication and encryption",
            "Change default community strings ('public', 'private')",
            "Restrict SNMP access to management hosts via ACL",
            "Disable SNMP if not required for network monitoring",
            "Block UDP port 161 at network perimeter",
        ],
    },

    "ldap": {
        "category":           "Directory Service",
        "subcategory":        "Lightweight Directory Access Protocol",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Discovery", "Credential Theft", "Lateral Movement"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm LDAP version and server software"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script ldap-rootdse {target}",
                 "purpose": "Retrieve LDAP root DSE — domain info, supported features"},
                {"tool": "ldapsearch", "command": "ldapsearch -x -h {target} -p {port} -b '' -s base",
                 "purpose": "Anonymous LDAP bind and base DN enumeration"},
            ],
            "High": [
                {"tool": "ldapsearch", "command": "ldapsearch -x -h {target} -p {port} -b 'DC=domain,DC=com' '(objectClass=*)'",
                 "purpose": "Dump all LDAP objects — users, groups, computers (anonymous if misconfigured)"},
                {"tool": "nmap",       "command": "nmap -p {port} --script ldap-search {target}",
                 "purpose": "NSE-based LDAP search for all objects"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/gather/ldap_query; set RHOSTS {target}; set RPORT {port}",
                 "purpose": "Metasploit LDAP enumeration with credential support"},
                {"tool": "bloodhound", "command": "bloodhound-python -d <domain> -u <user> -p <pass> -ns {target} -c All",
                 "purpose": "BloodHound Active Directory attack path collection"},
            ],
        },
        "hardening_checks": [
            "Disable anonymous LDAP bind — require authentication for all queries",
            "Migrate to LDAPS (port 636) — disable plain LDAP",
            "Restrict LDAP queries to necessary attributes only (LDAP ACLs)",
            "Monitor for unusual LDAP enumeration patterns",
        ],
    },

    "ldaps": {
        "category":           "Directory Service",
        "subcategory":        "LDAP over SSL/TLS",
        "protocol_cleartext": False,
        "anonymous_risk":     False,
        "attack_phases":      ["Discovery", "Credential Theft", "Lateral Movement"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV --script ssl-cert {target}",
                 "purpose": "Confirm LDAPS and inspect TLS certificate"},
            ],
            "Medium": [
                {"tool": "ldapsearch", "command": "ldapsearch -x -H ldaps://{target}:{port} -b '' -s base",
                 "purpose": "Anonymous LDAPS bind and base DN enumeration"},
            ],
            "High": [
                {"tool": "nmap",  "command": "nmap -p {port} --script ldap-rootdse,ldap-search {target}",
                 "purpose": "Full NSE LDAPS enumeration"},
            ],
            "Critical": [
                {"tool": "bloodhound", "command": "bloodhound-python -d <domain> -u <user> -p <pass> -ns {target} -c All",
                 "purpose": "BloodHound Active Directory attack path collection over LDAPS"},
            ],
        },
        "hardening_checks": [
            "Enforce LDAP channel binding and LDAP signing (MS KB4520412)",
            "Disable anonymous LDAP bind",
            "Restrict LDAPS access to authorised management hosts only",
            "Ensure TLS certificate is valid and uses strong cipher suites",
        ],
    },

    "msrpc": {
        "category":           "Infrastructure",
        "subcategory":        "Microsoft RPC Endpoint Mapper",
        "protocol_cleartext": False,
        "anonymous_risk":     True,
        "attack_phases":      ["Discovery", "Lateral Movement", "Execution"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2003-0352 — MS03-026 DCOM RPC buffer overflow (Blaster worm)",
            "CVE-2003-0715 — RPC endpoint mapper denial of service",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV {target}",
                 "purpose": "Confirm RPC endpoint mapper"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} --script msrpc-enum {target}",
                 "purpose": "Enumerate RPC endpoints — reveals running services"},
                {"tool": "rpcclient", "command": "rpcclient -U '' {target}",
                 "purpose": "Anonymous RPC session — enumerate users and domain info"},
            ],
            "High": [
                {"tool": "impacket", "command": "python3 rpcdump.py {target}",
                 "purpose": "Full RPC endpoint dump using Impacket"},
            ],
            "Critical": [
                {"tool": "msf",   "command": "use auxiliary/scanner/dcerpc/endpoint_mapper; set RHOSTS {target}",
                 "purpose": "Metasploit RPC endpoint mapper enumeration"},
            ],
        },
        "hardening_checks": [
            "Block port 135 at network perimeter",
            "Apply MS03-026 patch and all subsequent Windows security updates",
            "Restrict RPC access via Windows Firewall to management hosts only",
        ],
    },

    "ntp": {
        "category":           "Infrastructure",
        "subcategory":        "Time Synchronisation",
        "protocol_cleartext": True,
        "anonymous_risk":     True,
        "attack_phases":      ["Discovery", "Impact (DDoS amplification)"],
        "cve_prone":          True,
        "notable_cves": [
            "CVE-2013-5211 — NTP monlist DDoS amplification",
            "CVE-2014-9293 — NTP weak default key generation",
        ],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sU -sV {target}",
                 "purpose": "Confirm NTP service (UDP)"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} -sU --script ntp-info {target}",
                 "purpose": "Retrieve NTP server info, stratum, and reference clock"},
                {"tool": "nmap",  "command": "nmap -p {port} -sU --script ntp-monlist {target}",
                 "purpose": "Test for monlist amplification vulnerability (CVE-2013-5211)"},
            ],
            "High": [],
            "Critical": [],
        },
        "hardening_checks": [
            "Disable the monlist command (noquery in ntp.conf)",
            "Restrict NTP queries to authorised clients (restrict default noquery)",
            "Upgrade NTP daemon to latest version",
            "Use NTP authentication with symmetric keys",
        ],
    },

    # -----------------------------------------------------------------------
    # FALLBACK
    # -----------------------------------------------------------------------
    "unknown": {
        "category":           "Unknown",
        "subcategory":        "Unclassified Service",
        "protocol_cleartext": None,
        "anonymous_risk":     None,
        "attack_phases":      ["Discovery"],
        "cve_prone":          False,
        "notable_cves":       [],
        "enumeration": {
            "Low": [
                {"tool": "nmap",  "command": "nmap -p {port} -sV -sC {target}",
                 "purpose": "Version detection and default script scan — identify service"},
                {"tool": "nmap",  "command": "nmap -p {port} -sV --version-intensity 9 {target}",
                 "purpose": "Aggressive version detection for unknown service"},
            ],
            "Medium": [
                {"tool": "nmap",  "command": "nmap -p {port} -A {target}",
                 "purpose": "Aggressive scan — OS detection, version, scripts, traceroute"},
                {"tool": "nc",    "command": "nc -nv {target} {port}",
                 "purpose": "Raw banner grab — identify protocol by response"},
            ],
            "High": [],
            "Critical": [],
        },
        "hardening_checks": [
            "Identify this service and assess whether it should be exposed",
            "Close the port if the service is not required",
        ],
    },
}

# Service name aliases — maps scanner output names to KB keys
_ALIASES: dict[str, str] = {
    "microsoft-ds":  "smb",
    "ms-wbt-server": "rdp",
    "ms-sql-s":      "mssql",
    "netbios-ns":    "netbios-ssn",
    "http-alt":      "http",
    "http-rpc-epmap":"msrpc",
    "epmap":         "msrpc",
    "imaps":         "imap",
    "pop3s":         "pop3",
    "smtps":         "smtp",
    "submission":    "smtp",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze(service: str, port: int, risk_label: str = "Medium") -> dict:
    """
    Return the full intelligence record for a service, with enumeration commands
    gated to the supplied risk_label (cumulative — Critical includes all lower tiers).

    Lookup order: service name → alias → port map → 'unknown' fallback.
    """
    key    = service.lower().strip()
    key    = _ALIASES.get(key, key)
    record = _KB.get(key)

    if record is None:
        fallback_key = _PORT_MAP.get(port)
        if fallback_key:
            record = _KB.get(_ALIASES.get(fallback_key, fallback_key))

    if record is None:
        record = _KB["unknown"]

    return {
        "service":            key,
        "category":           record["category"],
        "subcategory":        record["subcategory"],
        "protocol_cleartext": record["protocol_cleartext"],
        "anonymous_risk":     record["anonymous_risk"],
        "attack_phases":      record["attack_phases"],
        "cve_prone":          record["cve_prone"],
        "notable_cves":       record["notable_cves"],
        "enum_commands":      _gate(record["enumeration"], risk_label),
        "hardening_checks":   record["hardening_checks"],
    }


def classify(service: str, port: int) -> str:
    """Return the category string for a service. Replaces classifier.classify_service()."""
    return analyze(service, port)["category"]


def enum_strings(service: str, port: int, risk_label: str = "Medium") -> list[str]:
    """
    Return enumeration commands as plain strings for backward-compatible consumers
    (e.g. formatter.py). Replaces enum_suggestions.suggest_enum().
    """
    intel = analyze(service, port, risk_label)
    return [cmd["command"] for cmd in intel["enum_commands"]]
