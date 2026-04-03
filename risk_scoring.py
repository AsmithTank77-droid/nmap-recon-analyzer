# risk_engine.py
# Part of: nmap-recon-analyzer
# Calculates risk scores for hosts and ports from parsed Nmap scan data.
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import logging
logger = logging.getLogger(__name__)
# ---------------------------------------------------------------------------
# Risk configuration
# ---------------------------------------------------------------------------
# Service-level base risk scores (1–10)
SERVICE_RISK: dict[str, int] = {
# Remote access — high exposure
"rdp": 9,
"vnc": 8,
"telnet": 9,
"ssh": 5,
# File transfer — credential exposure / data exfil
"ftp": 7,
"tftp": 7,
"smb": 8,
"netbios-ssn": 7,
# Web — broad attack surface
"http": 4,
"https": 3,
"http-proxy": 5,
# Database — critical data exposure
"mysql": 8,
"postgresql": 8,
"mssql": 8,
"oracle": 8,
"redis": 7,
"mongodb": 7,
"elasticsearch": 7,
# Mail
"smtp": 5,
"pop3": 5,
"imap": 5,
# DNS / infra
"domain": 4,
"snmp": 6,
"ntp": 2,
"ldap": 6,
"ldaps": 5,
# Other
"unknown": 4,
}
# Well-known risky port numbers (regardless of service name reported)
HIGH_RISK_PORTS: dict[int, str] = {
23: "Telnet",
445: "SMB",
135: "MS-RPC",
139: "NetBIOS",
3389: "RDP",
5900: "VNC",
1433: "MSSQL",
3306: "MySQL",
5432: "PostgreSQL",
6379: "Redis",
27017: "MongoDB",
9200: "Elasticsearch",
2049: "NFS",
111: "RPCBind",
512: "rexec",
513: "rlogin",
514: "rsh",
}
# Port-state multipliers
STATE_WEIGHT: dict[str, float] = {
"open": 1.0,
"filtered": 0.4,
"closed": 0.1,
}
# Severity thresholds (host-level composite score)
SEVERITY_THRESHOLDS = [
(8.0, "Critical"),
(6.0, "High"),
(4.0, "Medium"),
(2.0, "Low"),
(0.0, "Informational"),
]
# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class PortRisk:
port: int
protocol: str
service: str
state: str
base_score: float
weighted_score: float
flags: list[str] = field(default_factory=list) # e.g. ["well-known-risky-port"]
@dataclass
class HostRisk:
host: str
ports: list[PortRisk]
peak_score: float # highest single-port weighted score
composite_score: float # weighted combination of all ports
severity: str
risk_flags: list[str] # human-readable findings
# ---------------------------------------------------------------------------
# Core scoring logic
# ---------------------------------------------------------------------------
def _severity_label(score: float) -> str:
for threshold, label in SEVERITY_THRESHOLDS:
if score >= threshold:
return label
return "Informational"
def score_port(port_info: dict) -> PortRisk:
"""
Score a single port dict. Expected keys:
port (int), protocol (str), service (str), state (str)
"""
port_num = int(port_info.get("port", 0))
protocol = str(port_info.get("protocol", "tcp")).lower()
service = str(port_info.get("service", "unknown")).lower()
state = str(port_info.get("state", "open")).lower()
# Base score: service name takes priority; fall back to port-number lookup
if service in SERVICE_RISK:
base = float(SERVICE_RISK[service])
elif port_num in HIGH_RISK_PORTS:
base = 8.0 # known-risky port with unrecognised service name is suspicious
else:
base = float(SERVICE_RISK["unknown"])
flags: list[str] = []
# Boost for well-known risky ports even when service name matches
if port_num in HIGH_RISK_PORTS:
flags.append(f"well-known-risky-port ({HIGH_RISK_PORTS[port_num]})")
base = min(base + 1.0, 10.0)
# Non-standard port for a standard service is suspicious
STANDARD_PORTS = {22, 80, 443, 21, 25, 53, 110, 143, 3306, 5432, 6379}
if service not in ("unknown", "") and port_num not in STANDARD_PORTS and port_num not in
flags.append("non-standard port for service")
base = min(base + 0.5, 10.0)
weight = STATE_WEIGHT.get(state, 0.5)
weighted = round(base * weight, 2)
return PortRisk(
port=port_num,
protocol=protocol,
service=service,
state=state,
base_score=round(base, 2),
weighted_score=weighted,
flags=flags,
)
def score_host(host_info: dict) -> HostRisk:
"""
Score a host dict. Expected keys:
host (str), ports (list[dict])
"""
host = str(host_info.get("host", "unknown"))
raw_ports: list[dict] = host_info.get("ports", [])
if not raw_ports:
logger.warning("Host %s has no port data.", host)
return HostRisk(
host=host, ports=[], peak_score=0.0,
composite_score=0.0, severity="Informational", risk_flags=["no open ports detecte
)
scored_ports = [score_port(p) for p in raw_ports]
open_ports = [p for p in scored_ports if p.state == "open"]
scores = [p.weighted_score for p in scored_ports]
peak = max(scores)
# Composite: peak dominates (60 %) + mean of all open ports (40 %)
open_scores = [p.weighted_score for p in open_ports] or [0.0]
mean_open = sum(open_scores) / len(open_scores)
composite = round(0.6 * peak + 0.4 * mean_open, 2)
# Collect host-level flags
risk_flags: list[str] = []
for p in scored_ports:
risk_flags.extend([f"port {p.port}/{p.protocol} — {f}" for f in p.flags])
if len(open_ports) > 10:
risk_flags.append(f"large attack surface: {len(open_ports)} open ports")
return HostRisk(
host=host,
ports=scored_ports,
peak_score=round(peak, 2),
composite_score=composite,
severity=_severity_label(composite),
risk_flags=risk_flags,
)
def process_all_hosts(hosts: list[dict]) -> list[HostRisk]:
"""Score every host and return results sorted by composite score descending."""
results = [score_host(h) for h in hosts]
return sorted(results, key=lambda h: h.composite_score, reverse=True)
# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
def summary_report(host_risks: list[HostRisk]) -> str:
lines = ["=" * 60, "NMAP RECON ANALYZER — RISK SUMMARY", "=" * 60]
for hr in host_risks:
lines.append(
f"\nHost : {hr.host}"
f"\n Severity : {hr.severity}"
f"\n Composite : {hr.composite_score}/10"
f"\n Peak port : {hr.peak_score}/10"
)
if hr.risk_flags:
lines.append(" Flags:")
for flag in hr.risk_flags:
lines.append(f" • {flag}")
lines.append(" Open ports:")
for p in hr.ports:
if p.state == "open":
lines.append(
f" {p.port}/{p.protocol:<4} {p.service:<20}"
f" score={p.weighted_score}"
)
lines.append("\n" + "=" * 60)
return "\n".join(lines)
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
import sys
import json
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
scan_file = sys.argv[1] if len(sys.argv) > 1 else "scan.xml"
try:
from scan_xml import parse_scan # type: ignore
hosts = parse_scan(scan_file)
except FileNotFoundError:
logger.error("Scan file not found: %s", scan_file)
sys.exit(1)
except Exception as exc:
logger.error("Failed to parse scan file: %s", exc)
sys.exit(1)
results = process_all_hosts(hosts)
print(summary_report(results))
# Also dump machine-readable JSON
output = [
{
"host": hr.host,
"severity": hr.severity,
"composite_score": hr.composite_score,
"peak_score": hr.peak_score,
"risk_flags": hr.risk_flags,
"ports": [
{
"port": p.port,
"protocol": p.protocol,
"service": p.service,
"state": p.state,
"weighted_score": p.weighted_score,
"flags": p.flags,
}
for p in hr.ports
],
}
for hr in results
]
with open("risk_report.json", "w") as f:
json.dump(output, f, indent=2)
logger.info("JSON report written to risk_report.json")
