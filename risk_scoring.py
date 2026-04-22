# risk_scoring.py
# Part of: nmap-recon-analyzer
#
# SOC-style modular risk engine.
# Produces a 0-100 composite score with four named components,
# a risk level label, per-component structured reasoning, and
# colour-coded terminal output.
#
# Score budget
# ┌─────────────────┬────────┐
# │ Component       │ Max    │
# ├─────────────────┼────────┤
# │ service_risk    │  40    │
# │ exposure_risk   │  25    │
# │ attack_surface  │  20    │
# │ threat_context  │  15    │
# ├─────────────────┼────────┤
# │ TOTAL           │ 100    │
# └─────────────────┴────────┘

from __future__ import annotations
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ANSI colour helpers (gracefully ignored by non-colour terminals)
# ---------------------------------------------------------------------------
_C: dict[str, str] = {
    "Critical":      "\033[1;31m",   # bold red
    "High":          "\033[0;31m",   # red
    "Medium":        "\033[0;33m",   # yellow
    "Low":           "\033[0;32m",   # green
    "Informational": "\033[0;34m",   # blue
    "reset":         "\033[0m",
}

# ---------------------------------------------------------------------------
# Knowledge bases
# ---------------------------------------------------------------------------
SERVICE_RISK: dict[str, int] = {
    # Remote access — high direct exposure
    "rdp":           9,
    "vnc":           8,
    "telnet":        9,
    "ssh":           5,
    # File transfer
    "ftp":           7,
    "tftp":          7,
    "smb":           8,
    "netbios-ssn":   7,
    # Web
    "http":          4,
    "https":         3,
    "http-proxy":    5,
    # Database — critical data exposure
    "mysql":         8,
    "postgresql":    8,
    "mssql":         8,
    "oracle":        8,
    "redis":         7,
    "mongodb":       7,
    "elasticsearch": 7,
    # Mail
    "smtp":          5,
    "pop3":          5,
    "imap":          5,
    # Infrastructure
    "domain":        4,
    "snmp":          6,
    "ntp":           2,
    "ldap":          6,
    "ldaps":         5,
    # Fallback
    "unknown":       4,
}

HIGH_RISK_PORTS: dict[int, str] = {
    23:    "Telnet",
    111:   "RPCBind",
    135:   "MS-RPC",
    139:   "NetBIOS",
    445:   "SMB",
    512:   "rexec",
    513:   "rlogin",
    514:   "rsh",
    1433:  "MSSQL",
    2049:  "NFS",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

STANDARD_PORTS: set[int] = {
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 6379,
}

STATE_WEIGHT: dict[str, float] = {
    "open":     1.0,
    "filtered": 0.4,
    "closed":   0.1,
}

# Dangerous service pairs — each confirmed match adds +5 pts to attack_surface.
# Cap is 15 pts (3 combos). With 9 defined pairs there is now a real chance
# of hitting the cap on a heavily-exposed Windows or Linux server.
DANGEROUS_COMBOS: list[tuple[frozenset, str]] = [
    # Windows attack chains
    (frozenset({"smb",    "rdp"}),
        "SMB + RDP — classic ransomware staging environment"),
    (frozenset({"rdp",    "mssql"}),
        "RDP + MSSQL — Windows server with exposed DB and remote desktop"),
    (frozenset({"rdp",    "vnc"}),
        "RDP + VNC — dual remote-desktop paths, high takeover risk"),
    (frozenset({"smb",    "telnet"}),
        "SMB + Telnet — cleartext credentials combined with file sharing"),
    # Linux / web-app chains
    (frozenset({"ssh",    "ftp"}),
        "SSH + FTP — dual remote-access paths increase attack surface"),
    (frozenset({"ssh",    "mysql"}),
        "SSH + MySQL — Linux database server exposed, lateral-movement risk"),
    (frozenset({"http",   "mysql"}),
        "HTTP + MySQL — web app with exposed database layer"),
    (frozenset({"ftp",    "http"}),
        "FTP + HTTP — file upload via FTP may expose the web root"),
    (frozenset({"http",   "smb"}),
        "HTTP + SMB — pivot from web compromise to internal shares"),
]

# Services whose simultaneous presence raises concentration risk
DANGEROUS_SERVICES: set[str] = {
    "rdp", "smb", "telnet", "vnc", "ftp",
    "mssql", "mysql", "redis", "mongodb",
}

# 0-100 risk level thresholds (SOC-grade labels)
RISK_THRESHOLDS: list[tuple[int, str]] = [
    (75, "Critical"),
    (55, "High"),
    (35, "Medium"),
    (15, "Low"),
    (0,  "Informational"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _risk_level(score: int) -> str:
    """Map a 0-100 composite score to a named risk level."""
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "Informational"


def _port_risk_label(weighted_score: float) -> str:
    """Map a port weighted score (0-10) to a named risk label."""
    if   weighted_score >= 8.0: return "Critical"
    elif weighted_score >= 6.0: return "High"
    elif weighted_score >= 4.0: return "Medium"
    elif weighted_score >= 2.0: return "Low"
    else:                       return "Informational"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class PortRisk:
    port:           int
    protocol:       str
    service:        str
    state:          str
    base_score:     float
    weighted_score: float
    risk_label:     str               # Critical / High / Medium / Low / Informational
    flags:          list[str] = field(default_factory=list)


@dataclass
class ScoreComponent:
    score:     int
    max_score: int
    detail:    str


@dataclass
class HostRisk:
    host:                 str
    ports:                list[PortRisk]
    total_score:          int
    risk_level:           str
    breakdown:            dict[str, ScoreComponent]
    reasoning:            list[str]             # flat list — display & backward compat
    structured_reasoning: dict[str, list[str]]  # component → reason lines — JSON export
    # Backward-compatibility fields (pipeline consumers may depend on these)
    composite_score:  float       # = total_score / 10
    peak_score:       float       # highest individual port weighted_score
    severity:         str         # mirrors risk_level
    risk_flags:       list[str]   # mirrors reasoning


# ---------------------------------------------------------------------------
# Component scorer 1 — Service Risk  (max 40)
# ---------------------------------------------------------------------------
def _score_service_risk(
    open_ports: list[PortRisk],
) -> tuple[int, str, list[str]]:
    """
    Score the inherent danger of the services running on open ports.

    Peak service score drives 24 pts (worst-case triage focus).
    Mean across all open services drives 16 pts (breadth penalty).
    """
    if not open_ports:
        return 0, "0/40 — no open ports", []

    raw: list[tuple[float, PortRisk]] = []
    for p in open_ports:
        base = float(SERVICE_RISK.get(p.service, SERVICE_RISK["unknown"]))
        if p.port in HIGH_RISK_PORTS:
            base = min(base + 1.0, 10.0)
        raw.append((base, p))

    raw.sort(key=lambda x: x[0], reverse=True)
    scores   = [s for s, _ in raw]
    peak     = scores[0]
    mean     = sum(scores) / len(scores)

    peak_pts = round((peak / 10) * 24)
    mean_pts = round((mean / 10) * 16)
    total    = min(peak_pts + mean_pts, 40)

    reasons: list[str] = []
    top = raw[0][1]
    reasons.append(
        f"Highest-risk service: {top.service.upper()} on port {top.port} "
        f"(base score {peak:.0f}/10) — {peak_pts} pts."
    )
    if len(raw) > 1:
        others = ", ".join(f"{p.service.upper()}:{p.port}" for _, p in raw[1:4])
        reasons.append(f"Additional open services: {others}.")

    detail = (
        f"{total}/40 — peak {peak:.0f}/10 ({peak_pts} pts), "
        f"mean {mean:.1f}/10 ({mean_pts} pts) across {len(open_ports)} open port(s)"
    )
    return total, detail, reasons


# ---------------------------------------------------------------------------
# Component scorer 2 — Exposure Risk  (max 25)
# ---------------------------------------------------------------------------
def _score_exposure_risk(
    raw_ports:  list[dict],
    open_ports: list[PortRisk],
) -> tuple[int, str, list[str]]:
    """
    Score how broadly exposed the host is.

    Open port count (0-20, finer bins) + non-standard ports (+1 each, max 3)
    + filtered high-risk ports (+2 if any present).
    """
    reasons: list[str] = []
    n_open = len(open_ports)

    # Finer-grained bins than a simple step function
    if   n_open == 0:  count_pts = 0
    elif n_open == 1:  count_pts = 4
    elif n_open <= 3:  count_pts = 8
    elif n_open <= 6:  count_pts = 12
    elif n_open <= 10: count_pts = 16
    else:              count_pts = 20

    if n_open:
        reasons.append(f"{n_open} open port(s) detected (+{count_pts} pts).")

    nonstandard = [p for p in open_ports if p.port not in STANDARD_PORTS]
    ns_pts      = min(len(nonstandard), 3)
    if nonstandard:
        ns_str = ", ".join(str(p.port) for p in nonstandard[:5])
        reasons.append(f"Non-standard open port(s): {ns_str} (+{ns_pts} pts).")

    # Filtered high-risk ports are still informative: they may be reachable
    # from other network vantage points or only temporarily filtered.
    filtered_high = [
        p for p in raw_ports
        if str(p.get("state", "")).lower() == "filtered"
        and int(p.get("port", 0)) in HIGH_RISK_PORTS
    ]
    filt_pts = 2 if filtered_high else 0
    if filtered_high:
        fnames = ", ".join(HIGH_RISK_PORTS[int(p["port"])] for p in filtered_high[:3])
        reasons.append(
            f"Filtered high-risk port(s) detected ({fnames}) — "
            f"may be reachable from other positions (+{filt_pts} pts)."
        )

    total  = min(count_pts + ns_pts + filt_pts, 25)
    detail = (
        f"{total}/25 — {n_open} open ({count_pts} pts), "
        f"{len(nonstandard)} non-standard ({ns_pts} pts), "
        f"{len(filtered_high)} filtered high-risk ({filt_pts} pts)"
    )
    return total, detail, reasons


# ---------------------------------------------------------------------------
# Component scorer 3 — Attack Surface  (max 20)
# ---------------------------------------------------------------------------
def _score_attack_surface(
    open_ports: list[PortRisk],
) -> tuple[int, str, list[str]]:
    """
    Score dangerous service combinations and high-risk service concentration.

    Each matched dangerous pair: +5 pts (capped at 15 — three combos).
    Three or more individually dangerous services open simultaneously: +5 pts.
    """
    reasons:       list[str] = []
    service_names: set[str]  = {p.service.lower() for p in open_ports}

    combo_pts = 0
    n_combos  = 0
    for required, label in DANGEROUS_COMBOS:
        if required.issubset(service_names):
            combo_pts += 5
            n_combos  += 1
            reasons.append(f"Dangerous combination detected: {label}.")
    combo_pts = min(combo_pts, 15)

    n_dangerous       = sum(1 for p in open_ports if p.service.lower() in DANGEROUS_SERVICES)
    concentration_pts = 5 if n_dangerous >= 3 else 0
    if concentration_pts:
        names = ", ".join(
            p.service.upper()
            for p in open_ports
            if p.service.lower() in DANGEROUS_SERVICES
        )
        reasons.append(
            f"{n_dangerous} individually dangerous services open simultaneously "
            f"({names}) — elevated lateral movement risk (+5 pts)."
        )

    total  = min(combo_pts + concentration_pts, 20)
    detail = (
        f"{total}/20 — {combo_pts} pts from {n_combos} combo(s), "
        f"{concentration_pts} pts from concentration ({n_dangerous} dangerous service(s))"
    )
    return total, detail, reasons


# ---------------------------------------------------------------------------
# Component scorer 4 — Threat Context  (max 15)
# ---------------------------------------------------------------------------
def _score_threat_context(
    ip_context: dict | None,
) -> tuple[int, str, list[str]]:
    """
    Score based on IP reputation / geolocation from analyze_ip().

    Each signal is evaluated with mutually exclusive matching (first match wins
    per signal) to prevent double-counting from ambiguous signal strings.

    Proxy/VPN/Tor: +8  |  Data center: +5  |  Elevated-risk country: +5  |  Mobile: +1
    Score capped at 15.
    """
    if not ip_context:
        return 0, "0/15 — no IP context available", []

    reasons: list[str] = []
    score   = 0
    geo     = ip_context.get("geo_info", {})

    for sig in ip_context.get("signals", []):
        sl = sig.lower()
        # elif chain ensures each signal contributes exactly one bonus
        if any(k in sl for k in ("proxy", "vpn", "tor")):
            score += 8
            reasons.append("IP flagged as proxy, VPN, or Tor exit node (+8).")
        elif any(k in sl for k in ("data center", "hosting", "cloud")):
            score += 5
            reasons.append("IP hosted in a commercial data center / cloud provider (+5).")
        elif any(k in sl for k in ("elevated-risk", "high-risk country")):
            score += 5
            reasons.append(
                f"IP originates from elevated-risk country "
                f"({geo.get('country', 'unknown')}) (+5)."
            )
        elif "mobile" in sl:
            score += 1
            reasons.append("IP belongs to a mobile / cellular carrier (+1).")

    score  = min(score, 15)
    n_sigs = len(ip_context.get("signals", []))
    detail = f"{score}/15 — {n_sigs} signal(s) evaluated from IP enrichment"
    return score, detail, reasons


# ---------------------------------------------------------------------------
# Port-level scorer
# ---------------------------------------------------------------------------
def score_port(port_info: dict) -> PortRisk:
    """Score a single port dict. Expected keys: port, protocol, service, state."""
    port_num = int(port_info.get("port", 0))
    protocol = str(port_info.get("protocol", "tcp")).lower()
    service  = str(port_info.get("service", "unknown")).lower()
    state    = str(port_info.get("state", "open")).lower()

    if state not in STATE_WEIGHT:
        logger.debug(
            "Unrecognised port state '%s' on port %d — defaulting weight to 0.5.",
            state, port_num,
        )

    base   = float(SERVICE_RISK.get(service, SERVICE_RISK["unknown"]))
    flags: list[str] = []

    if port_num in HIGH_RISK_PORTS:
        flags.append(f"well-known-risky-port ({HIGH_RISK_PORTS[port_num]})")
        base = min(base + 1.0, 10.0)

    if (service not in ("unknown", "")
            and port_num not in STANDARD_PORTS
            and port_num not in HIGH_RISK_PORTS):
        flags.append("non-standard port for service")
        base = min(base + 0.5, 10.0)

    weighted = round(base * STATE_WEIGHT.get(state, 0.5), 2)

    return PortRisk(
        port=port_num,
        protocol=protocol,
        service=service,
        state=state,
        base_score=round(base, 2),
        weighted_score=weighted,
        risk_label=_port_risk_label(weighted),
        flags=flags,
    )


# ---------------------------------------------------------------------------
# Host scorer
# ---------------------------------------------------------------------------
def score_host(
    host_info:  dict,
    ip_context: dict | None = None,
) -> HostRisk:
    """
    Score a single host across all four components.

    host_info  : {"host": str, "ports": list[dict]}
    ip_context : optional result of threat_context.analyze_ip(ip)
    """
    host      = str(host_info.get("host", "unknown"))
    raw_ports = host_info.get("ports", [])

    _empty_breakdown = {
        "service_risk":   ScoreComponent(0, 40, "no port data"),
        "exposure_risk":  ScoreComponent(0, 25, "no port data"),
        "attack_surface": ScoreComponent(0, 20, "no port data"),
        "threat_context": ScoreComponent(0, 15, "no port data"),
    }

    if not raw_ports:
        logger.warning("Host %s has no port data.", host)
        fallback = ["No port data available for this host."]
        return HostRisk(
            host=host, ports=[], total_score=0, risk_level="Informational",
            breakdown=_empty_breakdown,
            reasoning=fallback,
            structured_reasoning={k: [] for k in _empty_breakdown},
            composite_score=0.0, peak_score=0.0,
            severity="Informational", risk_flags=fallback,
        )

    scored_ports = [score_port(p) for p in raw_ports]
    open_ports   = [p for p in scored_ports if p.state == "open"]

    svc_pts, svc_detail, svc_reasons = _score_service_risk(open_ports)
    exp_pts, exp_detail, exp_reasons = _score_exposure_risk(raw_ports, open_ports)
    atk_pts, atk_detail, atk_reasons = _score_attack_surface(open_ports)
    ctx_pts, ctx_detail, ctx_reasons = _score_threat_context(ip_context)

    total      = svc_pts + exp_pts + atk_pts + ctx_pts
    risk_level = _risk_level(total)

    breakdown = {
        "service_risk":   ScoreComponent(svc_pts, 40, svc_detail),
        "exposure_risk":  ScoreComponent(exp_pts, 25, exp_detail),
        "attack_surface": ScoreComponent(atk_pts, 20, atk_detail),
        "threat_context": ScoreComponent(ctx_pts, 15, ctx_detail),
    }

    # Structured reasoning: per-component reason lines — used in JSON export
    structured_reasoning: dict[str, list[str]] = {
        "service_risk":   svc_reasons,
        "exposure_risk":  exp_reasons,
        "attack_surface": atk_reasons,
        "threat_context": ctx_reasons,
    }

    # Flat list for terminal display and backward compat
    reasoning = svc_reasons + exp_reasons + atk_reasons + ctx_reasons
    if not reasoning:
        reasoning = [
            "All detected ports are closed or filtered. "
            "No active risk indicators found — monitor for state changes."
        ]
        structured_reasoning = {k: [] for k in breakdown}

    peak_weighted = max((p.weighted_score for p in scored_ports), default=0.0)

    return HostRisk(
        host=host,
        ports=scored_ports,
        total_score=total,
        risk_level=risk_level,
        breakdown=breakdown,
        reasoning=reasoning,
        structured_reasoning=structured_reasoning,
        # Backward-compat
        composite_score=round(total / 10, 2),
        peak_score=round(peak_weighted, 2),
        severity=risk_level,
        risk_flags=reasoning,
    )


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------
def process_all_hosts(
    hosts:       list[dict],
    ip_contexts: dict[str, dict] | None = None,
) -> list[HostRisk]:
    """
    Score every host. Returns results sorted by total_score descending.

    ip_contexts : optional {host_ip: analyze_ip() result}
    """
    ip_contexts = ip_contexts or {}
    results = [
        score_host(h, ip_contexts.get(h.get("host")))
        for h in hosts
    ]
    return sorted(results, key=lambda h: h.total_score, reverse=True)


# ---------------------------------------------------------------------------
# Analyzer.py compatibility helper
# ---------------------------------------------------------------------------
def _host_to_threat_services(host_risk: HostRisk) -> list[dict]:
    """
    Convert open ports to the format expected by threat_context.generate_threat_insights.

    Maps PortRisk.risk_label → HIGH / MEDIUM / LOW tier expected by the threat module.
    """
    _to_tier: dict[str, str] = {
        "Critical":      "HIGH",
        "High":          "HIGH",
        "Medium":        "MEDIUM",
        "Low":           "LOW",
        "Informational": "LOW",
    }
    return [
        {
            "port":    p.port,
            "service": p.service,
            "risk":    _to_tier.get(p.risk_label, "LOW"),
        }
        for p in host_risk.ports
        if p.state == "open"
    ]


# ---------------------------------------------------------------------------
# Terminal report  (colour-coded, sorted ports, per-port risk labels)
# ---------------------------------------------------------------------------
def summary_report(host_risks: list[HostRisk]) -> str:
    W = 65
    lines = ["=" * W, "  NMAP RECON ANALYZER — RISK ENGINE REPORT", "=" * W]

    for hr in host_risks:
        lvl_c  = _C.get(hr.risk_level, "")
        reset  = _C["reset"]
        n_open = sum(1 for p in hr.ports if p.state == "open")

        lines.append(
            f"\nHost        : {hr.host}"
            f"\n  Risk Level  : {lvl_c}{hr.risk_level}{reset}"
            f"\n  Total Score : {lvl_c}{hr.total_score}/100{reset}"
        )

        lines.append("  Score Breakdown:")
        for name, comp in hr.breakdown.items():
            pct    = comp.score / comp.max_score if comp.max_score else 0
            filled = round(pct * 20)
            bar    = "█" * filled + "░" * (20 - filled)
            lines.append(
                f"    {name:<16} [{bar}] {comp.score:>3}/{comp.max_score}"
            )
            lines.append(f"                       {comp.detail}")

        if hr.reasoning:
            lines.append("  Reasoning:")
            for r in hr.reasoning:
                lines.append(f"    • {r}")

        lines.append(f"  Open ports ({n_open}):")
        for p in sorted(hr.ports, key=lambda x: x.port):
            if p.state != "open":
                continue
            pc = _C.get(p.risk_label, "")
            lines.append(
                f"    {p.port:<6}/{p.protocol:<5} {p.service:<22} "
                f"{pc}{p.risk_label:<14}{reset} score={p.weighted_score}"
            )

    lines.append("\n" + "=" * W)
    return "\n".join(lines)
