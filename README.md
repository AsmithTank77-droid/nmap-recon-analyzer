# Nmap Recon Analyzer

A SOC-grade Nmap XML analysis pipeline that transforms raw scan data into structured risk assessments, threat intelligence, and actionable remediation guidance.

Point it at an Nmap XML file. Get back a colour-coded terminal report, a per-host risk score with full reasoning, service-specific CVE references, risk-gated enumeration commands, and a SIEM-ready JSON report — all from pure Python with zero third-party dependencies.

---

## What it does

Most Nmap post-processors stop at "list open ports and suggest some commands." This tool runs a six-stage analysis pipeline:

1. **Parse** — Nmap XML → structured host/port records
2. **Classify** — every port mapped to a service category and security profile
3. **Risk Score** — four-component composite score (0–100) with per-component reasoning
4. **Threat Enrichment** — IP geolocation, threat signals, and dangerous service combination detection
5. **Assemble** — final report written as JSON, SOC report printed to terminal
6. **Recommended Actions** — per-port SOC triage actions with priority, service context, and rationale

The output is framed for a SOC analyst doing triage, not an attacker looking for an entry point.

---

## Key features

**Four-component risk model**
Every host receives a composite score built from four independent components, each with its own score budget and reasoning. The breakdown is visible in both the terminal output and the JSON report.

**Service intelligence knowledge base**
27 services are covered end-to-end: category, MITRE ATT&CK phases, cleartext/anonymous-access flags, notable CVE history, risk-gated enumeration commands (cumulative by tier: Low → Medium → High → Critical), and hardening checks.

**Risk-gated enumeration commands**
Enumeration commands are unlocked progressively. A Low-risk port shows only version-detection commands. A Critical-risk port surfaces everything up to and including Metasploit modules. Commands are pre-filled with the real target IP and port — no placeholders left behind.

**Dangerous service combination detection**
Nine pre-defined service pairs that represent real-world attack chains (SMB + RDP, HTTP + MySQL, SSH + FTP, etc.) are checked across each host. Each confirmed combination adds to the attack surface score and surfaces a labelled flag in the report.

**Threat context enrichment**
Every host IP is queried against ip-api.com (no API key needed). Proxy/VPN/Tor flags, data centre hosting, mobile carrier, and elevated-risk country signals are evaluated and factored into the composite score.

**SOC recommended actions**
`recommended_actions_engine.py` produces a prioritised action list per host (P1–P5), including immediate triage step, enumeration checklist, hardening items, and relevant CVEs.

**Zero external dependencies**
Pure Python 3.8+ standard library. No pip install required.

**JSON / SIEM-ready output**
The full report — scores, reasoning, CVEs, threat signals, enumeration commands — is serialised to a structured JSON file ready to ship to Splunk, Elasticsearch, or any SIEM.

---

## Five-stage pipeline

```
  Nmap XML file
       │
       ▼
┌─────────────┐
│  1. Parse   │  scan_xml.py — parse hosts, ports, services, states
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  2. Classify     │  service_intelligence.py — category, CVEs, attack phases
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  3. Risk Engine  │  risk_scoring.py — 4-component 0–100 composite score
└──────┬───────────┘
       │
       ▼
┌─────────────────────┐
│  4. Threat Context  │  threat_context.py — IP enrichment, combo detection
└──────┬──────────────┘
       │
       ▼
┌───────────────────────┐
│  5. Assemble & Export │  analyzer.py — JSON report + terminal SOC output
└──────┬────────────────┘
       │
       ▼
┌──────────────────────────┐
│  6. Recommended Actions  │  recommended_actions_engine.py — P1–P5 SOC triage actions
└──────────────────────────┘
```

---

## Risk scoring model

The composite score runs 0–100 and maps to five severity levels: **Critical**, **High**, **Medium**, **Low**, **Informational**.

| Component | Max | What it measures |
|---|---|---|
| `service_risk` | 40 | Inherent danger of running services — peak service score (24 pts) + mean across all open ports (16 pts) |
| `exposure_risk` | 25 | Breadth of exposure — open port count, non-standard ports, filtered high-risk ports |
| `attack_surface` | 20 | Dangerous service combinations (up to 3 × +5 pts) + dangerous service concentration (+5 pts) |
| `threat_context` | 15 | IP threat signals — proxy/VPN/Tor (+8), data centre (+5), elevated-risk country (+5), mobile (+1) |
| **Total** | **100** | |

Score thresholds:

| Score | Level |
|---|---|
| ≥ 75 | Critical |
| ≥ 55 | High |
| ≥ 35 | Medium |
| ≥ 15 | Low |
| < 15 | Informational |

---

## Service intelligence coverage

| Category | Services |
|---|---|
| Remote Access | SSH, Telnet, RDP, VNC |
| File Transfer | FTP, TFTP |
| File Sharing | SMB, NetBIOS, NFS |
| Web | HTTP, HTTPS, HTTP Proxy |
| Database | MySQL, PostgreSQL, MSSQL, Redis, MongoDB, Elasticsearch |
| Email | SMTP, POP3, IMAP |
| Infrastructure | DNS, SNMP, NTP, MS-RPC |
| Directory | LDAP, LDAPS |

Each service record includes:
- MITRE ATT&CK-aligned attack phases
- Cleartext credential risk flag
- Anonymous / unauthenticated access flag
- Notable CVE history
- Tiered enumeration commands (Low / Medium / High / Critical)
- Hardening checks for remediation

---

## Dangerous service combination detection

Nine service pairs that represent real attack chains are tracked across each host:

| Combination | Risk |
|---|---|
| SMB + RDP | Classic ransomware staging environment |
| RDP + MSSQL | Windows server with exposed DB and remote desktop |
| RDP + VNC | Dual remote-desktop paths, high takeover risk |
| SMB + Telnet | Cleartext credentials combined with file sharing |
| SSH + FTP | Dual remote-access paths increase attack surface |
| SSH + MySQL | Linux database server exposed, lateral movement risk |
| HTTP + MySQL | Web application with exposed database layer |
| FTP + HTTP | File upload via FTP may expose the web root |
| HTTP + SMB | Pivot from web compromise to internal shares |

---

## Installation

No dependencies to install. Python 3.8 or later is required.

```bash
git clone https://github.com/AsmithTank77-droid/nmap-recon-analyzer.git
cd nmap-recon-analyzer
```

Generate an Nmap XML scan to analyze:

```bash
nmap -sV -oX scan.xml <target>
```

---

## Usage

```
usage: nmap-recon-analyzer [-h] [--output FILE] [--quiet] scan_file

Parse an Nmap XML scan and produce a SOC-style risk report with
service intelligence, threat context, and recommended actions.

positional arguments:
  scan_file             Path to the Nmap XML output file (nmap -oX scan.xml ...)

options:
  -h, --help            show this help message and exit
  --output FILE, -o FILE
                        Path for the JSON report output (default: risk_report.json)
  --quiet, -q           Suppress terminal output — write JSON report only

Examples:
  python3 analyzer.py scan.xml
  python3 analyzer.py scan.xml --output results/report.json
  python3 analyzer.py scan.xml --quiet
```

---

## Sample terminal output

```
[1/5] Parsing scan file...
[2/5] Classifying services...
[3/5] Running risk engine...

=================================================================
  NMAP RECON ANALYZER — RISK ENGINE REPORT
=================================================================

Host        : 192.168.1.50
  Risk Level  : Critical
  Total Score : 82/100
  Score Breakdown:
    service_risk     [████████████████░░░░]  35/40
                       35/40 — peak 9/10 (22 pts), mean 6.8/10 (11 pts) across 4 open port(s)
    exposure_risk    [████████░░░░░░░░░░░░]  12/25
                       12/25 — 4 open (12 pts), 0 non-standard (0 pts), 0 filtered high-risk (0 pts)
    attack_surface   [████████████████████]  20/20
                       20/20 — 15 pts from 3 combo(s), 5 pts from concentration (4 dangerous services)
    threat_context   [████████████████████]  15/15
                       15/15 — 2 signal(s) evaluated from IP enrichment
  Reasoning:
    • Highest-risk service: RDP on port 3389 (base score 9/10) — 22 pts.
    • Additional open services: SMB:445, SSH:22, HTTP:80.
    • 4 open port(s) detected (+12 pts).
    • Dangerous combination detected: SMB + RDP — classic ransomware staging environment.
    • Dangerous combination detected: HTTP + SMB — pivot from web compromise to internal shares.
    • 4 individually dangerous services open simultaneously — elevated lateral movement risk.
    • IP is hosted in a commercial data center / cloud provider (+5).
    • IP identified as proxy, VPN, or Tor exit node (+8).
  Open ports (4):
    22    /tcp   ssh                    Medium         score=5.0
    80    /tcp   http                   Medium         score=4.0
    445   /tcp   smb                    High           score=8.0
    3389  /tcp   rdp                    Critical       score=9.0

=================================================================

[4/5] Enriching with threat context...

============================================================
  THREAT CONTEXT ANALYSIS
============================================================

--- Host: 192.168.1.50 ---
  Location : Frankfurt, Germany
  Org      : AS16276 OVH SAS
  IP Risk  : HIGH
  Signal   : IP is hosted in a commercial data center / cloud provider.
  Signal   : IP identified as proxy, VPN, or Tor exit node.

============================================================
  THREAT CONTEXT REPORT
  !! HIGH-VALUE TARGET — multiple critical services exposed !!
============================================================

[Port 22]  SSH  —  Risk: HIGH
  Threat : Brute-force attacks — attackers use automated tools (Hydra, Medusa)
           to guess credentials and gain shell access.
  FLAG   : COMBO: SMB + RDP present — classic ransomware staging environment.

[Port 445]  SMB  —  Risk: HIGH
  Threat : Lateral movement / ransomware — SMB vulnerabilities (e.g. EternalBlue)
           are exploited to spread across networks and deploy ransomware.

[Port 3389]  RDP  —  Risk: HIGH
  Threat : Remote access compromise — exposed RDP is a top ransomware entry point;
           credential stuffing and BlueKeep-style exploits are common.

[5/5] Assembling final report...

============================================================
  SOC REPORT — 192.168.1.50
============================================================

PORT      PROTOCOL   SERVICE        RISK
22        tcp        ssh            Medium
80        tcp        http           Medium
445       tcp        smb            High
3389      tcp        rdp            Critical

ENUMERATION COMMANDS (risk-gated):
Port 445 (smb) — High:
  nmap -p 445 -sV 192.168.1.50
  nmap -p 445 --script smb-security-mode 192.168.1.50
  nmap -p 445 --script smb-enum-shares,smb-enum-users 192.168.1.50
  nmap -p 445 --script smb-vuln-ms17-010 192.168.1.50
  crackmapexec smb 192.168.1.50 -u users.txt -p passwords.txt

Port 3389 (rdp) — Critical:
  nmap -p 3389 -sV 192.168.1.50
  nmap -p 3389 --script rdp-enum-encryption 192.168.1.50
  nmap -p 3389 --script rdp-vuln-ms12-020 192.168.1.50
  hydra -L users.txt -P passwords.txt rdp://192.168.1.50:3389
  use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS 192.168.1.50

INFO: risk_report.json written (1 host(s)).
```

---

## JSON output schema

The report written to `risk_report.json` follows this structure:

```json
{
  "meta": {
    "generated_at": "2025-04-22T14:30:00+00:00",
    "source_file": "scan.xml",
    "host_count": 1,
    "analyzer": "nmap-recon-analyzer"
  },
  "hosts": [
    {
      "host": "192.168.1.50",
      "risk_level": "Critical",
      "total_score": 82,
      "score_breakdown": {
        "service_risk":   { "score": 35, "max_score": 40, "detail": "..." },
        "exposure_risk":  { "score": 12, "max_score": 25, "detail": "..." },
        "attack_surface": { "score": 20, "max_score": 20, "detail": "..." },
        "threat_context": { "score": 15, "max_score": 15, "detail": "..." }
      },
      "reasoning": ["..."],
      "structured_reasoning": {
        "service_risk":   ["..."],
        "exposure_risk":  ["..."],
        "attack_surface": ["..."],
        "threat_context": ["..."]
      },
      "high_value_target": true,
      "threat_context": {
        "ip_info":  { "ip": "...", "hostname": "...", "org": "...", "isp": "...", "asn": "..." },
        "geo_info": { "country": "...", "city": "...", "lat": 0.0, "lon": 0.0, "timezone": "..." },
        "signals":  ["..."],
        "risk":     "HIGH"
      },
      "ports": [
        {
          "port": 3389,
          "protocol": "tcp",
          "service": "rdp",
          "state": "open",
          "category": "Remote Access",
          "subcategory": "Remote Desktop",
          "protocol_cleartext": false,
          "anonymous_risk": false,
          "attack_phases": ["Initial Access", "Lateral Movement", "Defense Evasion", "Persistence"],
          "cve_prone": true,
          "notable_cves": ["CVE-2019-0708 — BlueKeep unauthenticated RCE"],
          "weighted_score": 9.0,
          "risk": "Critical",
          "risk_flags": ["well-known-risky-port (RDP)"],
          "threat": "Remote access compromise...",
          "threat_flags": ["COMBO: SMB + RDP present..."],
          "hardening_checks": ["Enforce Network Level Authentication (NLA)", "..."],
          "enum_commands": [{ "tool": "nmap", "command": "...", "purpose": "..." }]
        }
      ]
    }
  ]
}
```

---

## Module overview

| Module | Role |
|---|---|
| `analyzer.py` | Main pipeline — orchestrates all six stages, argparse CLI |
| `scan_xml.py` | Nmap XML parser, returns structured host/port records |
| `service_intelligence.py` | Unified service knowledge base — 27 services, CVEs, MITRE phases, enum commands, hardening checks |
| `risk_scoring.py` | Four-component scoring engine, `HostRisk` / `PortRisk` data classes |
| `threat_context.py` | Threat insights and IP enrichment via ip-api.com |
| `recommended_actions_engine.py` | SOC-style recommended actions per host (P1–P5 priority) |
| `formatter.py` | Terminal output formatter — colour-coded SOC report and recommended actions |
| `tests/test_risk_scoring.py` | 54 unit tests — scoring thresholds, components, edge cases |
| `tests/test_service_intelligence.py` | 36 unit tests — classification, alias resolution, risk gating |
| `tests/test_scan_xml.py` | 22 unit tests — parsing, IPv6, missing fields, error handling |

---

## Requirements

- Python 3.8 or later
- No third-party packages — standard library only
- Nmap installed separately to generate scan files

---

## Disclaimer

This tool is intended for authorised security assessments, penetration testing engagements, SOC triage work, and educational use. Always obtain written permission before scanning any network or system you do not own. The authors accept no liability for misuse.

---

## Author

**AsmithTank77-droid**  
Security analyst | Python developer
