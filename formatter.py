# formatter.py
# Part of: nmap-recon-analyzer
#
# Terminal output formatter for the SOC report stage.
# Receives the full assembled data from analyzer.py (step 5) and prints
# a structured, colour-coded report per host.
#
# Public API
# ----------
# format_output(hr, ports_json)
#   hr         — HostRisk dataclass from risk_scoring.py
#   ports_json — list of fully assembled port dicts from analyzer.py

from __future__ import annotations

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
_C: dict[str, str] = {
    "Critical":      "\033[1;31m",   # bold red
    "High":          "\033[0;31m",   # red
    "Medium":        "\033[0;33m",   # yellow
    "Low":           "\033[0;32m",   # green
    "Informational": "\033[0;34m",   # blue
    "reset":         "\033[0m",
    "bold":          "\033[1m",
    "dim":           "\033[2m",
}

_RISK_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

W = 70   # report width


def _col(risk: str, text: str) -> str:
    return f"{_C.get(risk, '')}{text}{_C['reset']}"


def _divider(char: str = "─") -> str:
    return char * W


def _header(title: str) -> str:
    return f"{_C['bold']}{title}{_C['reset']}"


# ---------------------------------------------------------------------------
# Section: port overview table
# ---------------------------------------------------------------------------
def _port_table(ports_json: list[dict]) -> None:
    print()
    print(_divider("═"))
    print(_header("  PORT OVERVIEW"))
    print(_divider("═"))

    hdr = (
        f"{'PORT':<7} {'PROTO':<6} {'SERVICE':<20} "
        f"{'CATEGORY':<18} {'RISK':<22} {'SCORE'}"
    )
    print(f"{_C['bold']}{_C['dim']}{hdr}{_C['reset']}")
    print(_divider())

    for p in sorted(ports_json, key=lambda x: x["port"]):
        risk       = p.get("risk", "Informational")
        score      = p.get("weighted_score", 0.0)
        risk_col   = _col(risk, f"{risk:<14}")
        state      = p.get("state", "open")
        state_note = "" if state == "open" else f" [{state}]"
        print(
            f"{str(p['port']):<7} {p['protocol']:<6} "
            f"{(p['service'] + state_note):<20} "
            f"{p.get('category', ''):<18} "
            f"{risk_col}  {score:.1f}"
        )

    print(_divider())


# ---------------------------------------------------------------------------
# Section: detailed port block (Critical / High)
# ---------------------------------------------------------------------------
def _detail_block(p: dict) -> None:
    risk       = p.get("risk", "Informational")
    port       = p["port"]
    proto      = p["protocol"]
    service    = p["service"]
    subcat     = p.get("subcategory", "")
    score      = p.get("weighted_score", 0.0)
    cleartext  = p.get("protocol_cleartext")
    anon       = p.get("anonymous_risk")
    phases     = p.get("attack_phases", [])
    threat     = p.get("threat")
    flags      = p.get("risk_flags", []) + p.get("threat_flags", [])
    cves       = p.get("notable_cves", [])
    hardening  = p.get("hardening_checks", [])
    enum_cmds  = p.get("enum_commands", [])

    print()
    print(_divider())
    label = _col(risk, f"[{risk.upper()}]")
    print(f"  {label}  {_C['bold']}{port}/{proto}  {service}{_C['reset']}"
          + (f"  —  {subcat}" if subcat else ""))
    print(_divider())

    # Score line
    print(f"  {'Score':<16}  {score:.1f} / 10")

    # Cleartext / anonymous flags
    def _yn(val) -> str:
        if val is True:  return _col("High",          "Yes")
        if val is False: return _col("Low",            "No")
        return _col("Informational", "Unknown")

    print(f"  {'Cleartext':<16}  {_yn(cleartext)}    "
          f"Anonymous Access  {_yn(anon)}")

    # MITRE ATT&CK phases
    if phases:
        phase_str = "  /  ".join(phases)
        print(f"  {'ATT&CK':<16}  {phase_str}")

    # Threat description
    if threat:
        wrapped = _wrap(threat, indent=20, width=W)
        print(f"  {'Threat':<16}  {wrapped}")

    # Flags (risk flags + combo warnings)
    unique_flags = list(dict.fromkeys(flags))
    for flag in unique_flags:
        print(f"  {'Flag':<16}  {_col('High', flag)}")

    # CVEs
    if cves:
        print()
        print(f"  {_C['bold']}Notable CVEs{_C['reset']}")
        for cve in cves:
            print(f"    {_C['dim']}▸{_C['reset']}  {cve}")

    # Hardening checks
    if hardening:
        print()
        print(f"  {_C['bold']}Hardening Checks{_C['reset']}")
        for i, check in enumerate(hardening, 1):
            print(f"    {i:>2}.  {check}")

    # Enumeration commands
    if enum_cmds:
        tier = risk
        print()
        print(f"  {_C['bold']}Enumeration Commands{_C['reset']}  "
              f"{_C['dim']}[{tier} tier]{_C['reset']}")
        for cmd in enum_cmds:
            tool    = cmd.get("tool", "")
            command = cmd.get("command", "")
            purpose = cmd.get("purpose", "")
            print(f"    {_C['bold']}[{tool}]{_C['reset']}")
            print(f"      {command}")
            if purpose:
                print(f"      {_C['dim']}{purpose}{_C['reset']}")


# ---------------------------------------------------------------------------
# Section: summary block (Medium)
# ---------------------------------------------------------------------------
def _summary_block(p: dict) -> None:
    risk      = p.get("risk", "Medium")
    port      = p["port"]
    proto     = p["protocol"]
    service   = p["service"]
    subcat    = p.get("subcategory", "")
    score     = p.get("weighted_score", 0.0)
    phases    = p.get("attack_phases", [])
    cves      = p.get("notable_cves", [])
    hardening = p.get("hardening_checks", [])
    enum_cmds = p.get("enum_commands", [])
    threat    = p.get("threat")
    flags     = p.get("risk_flags", []) + p.get("threat_flags", [])

    print()
    print(_divider())
    label = _col(risk, f"[{risk.upper()}]")
    print(f"  {label}  {_C['bold']}{port}/{proto}  {service}{_C['reset']}"
          + (f"  —  {subcat}" if subcat else ""))
    print(_divider())

    print(f"  {'Score':<16}  {score:.1f} / 10")

    if phases:
        print(f"  {'ATT&CK':<16}  {'  /  '.join(phases)}")

    if threat:
        wrapped = _wrap(threat, indent=20, width=W)
        print(f"  {'Threat':<16}  {wrapped}")

    unique_flags = list(dict.fromkeys(flags))
    for flag in unique_flags:
        print(f"  {'Flag':<16}  {_col('Medium', flag)}")

    if cves:
        print()
        print(f"  {_C['bold']}Notable CVEs{_C['reset']}")
        for cve in cves:
            print(f"    {_C['dim']}▸{_C['reset']}  {cve}")

    if hardening:
        print()
        print(f"  {_C['bold']}Top Hardening Checks{_C['reset']}")
        for i, check in enumerate(hardening[:3], 1):
            print(f"    {i:>2}.  {check}")
        remaining = len(hardening) - 3
        if remaining > 0:
            print(f"        {_C['dim']}(+{remaining} more — see JSON report){_C['reset']}")

    if enum_cmds:
        print()
        print(f"  {_C['bold']}Enumeration Commands{_C['reset']}  "
              f"{_C['dim']}[Medium tier]{_C['reset']}")
        for cmd in enum_cmds:
            tool    = cmd.get("tool", "")
            command = cmd.get("command", "")
            purpose = cmd.get("purpose", "")
            print(f"    {_C['bold']}[{tool}]{_C['reset']}")
            print(f"      {command}")
            if purpose:
                print(f"      {_C['dim']}{purpose}{_C['reset']}")


# ---------------------------------------------------------------------------
# Text wrapper (no external dependencies)
# ---------------------------------------------------------------------------
def _wrap(text: str, indent: int, width: int) -> str:
    """Wrap text to width, indenting continuation lines."""
    words     = text.split()
    lines:    list[str] = []
    line:     list[str] = []
    line_len  = 0
    avail     = width - indent

    for word in words:
        if line_len + len(word) + (1 if line else 0) > avail:
            lines.append(" ".join(line))
            line     = [word]
            line_len = len(word)
        else:
            line.append(word)
            line_len += len(word) + (1 if len(line) > 1 else 0)

    if line:
        lines.append(" ".join(line))

    pad = " " * indent
    return f"\n{pad}".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def format_recommended_actions(rec: dict) -> None:
    """
    Print a compact recommended actions summary for one host.

    rec — one element from recommended_actions_engine.generate_recommendations()
    """
    ip         = rec.get("ip", "unknown")
    risk_level = rec.get("overall_risk_level", "Unknown")
    summary    = rec.get("overall_host_summary", "")
    recs       = rec.get("recommendations", [])

    print()
    print(_divider("═"))
    label = _col(risk_level, f"[{risk_level.upper()}]")
    print(_header(f"  RECOMMENDED ACTIONS — {ip}  {label}"))
    print(_divider("═"))

    if summary:
        print(f"  {_wrap(summary, indent=2, width=W)}")

    if not recs:
        print(f"  {_C['dim']}No actionable recommendations for this host.{_C['reset']}")
        print(_divider())
        return

    print()
    for r in recs:
        priority = r.get("priority", 5)
        port     = r.get("port")
        proto    = r.get("protocol", "tcp")
        service  = r.get("service", "unknown")
        category = r.get("category", "")
        rlevel   = r.get("risk_level", "Informational")
        action   = r.get("action_taken", "")

        risk_col = _col(rlevel, f"P{priority}")
        print(f"  {risk_col}  {port}/{proto}  {_C['bold']}{service}{_C['reset']}"
              + (f"  ({category})" if category else ""))
        if action:
            wrapped = _wrap(action, indent=6, width=W)
            print(f"      {wrapped}")
        print()

    print(f"  {_C['dim']}Full service context, CVEs, and hardening checks: risk_report.json{_C['reset']}")
    print(_divider())


def format_output(hr, ports_json: list[dict]) -> None:
    """
    Print the full SOC report for a single host.

    hr         — HostRisk from risk_scoring.py (host, risk_level, total_score)
    ports_json — list of assembled port dicts from analyzer.py step 5
    """
    _port_table(ports_json)

    # Sort by risk severity then port number
    risk_index = {r: i for i, r in enumerate(_RISK_ORDER)}
    ordered    = sorted(
        ports_json,
        key=lambda p: (risk_index.get(p.get("risk", "Informational"), 99), p["port"]),
    )

    critical_high = [p for p in ordered if p.get("risk") in ("Critical", "High")]
    medium        = [p for p in ordered if p.get("risk") == "Medium"]

    if critical_high:
        print()
        print(_divider("═"))
        print(_header("  CRITICAL & HIGH — FULL DETAIL"))
        print(_divider("═"))
        for p in critical_high:
            _detail_block(p)

    if medium:
        print()
        print(_divider("═"))
        print(_header("  MEDIUM RISK — SUMMARY"))
        print(_divider("═"))
        for p in medium:
            _summary_block(p)

    low_info = [p for p in ordered if p.get("risk") in ("Low", "Informational")]
    if low_info:
        print()
        print(_divider("═"))
        print(_header("  LOW / INFORMATIONAL"))
        print(_divider("═"))
        for p in low_info:
            risk = p.get("risk", "Informational")
            print(f"  {_col(risk, f'[{risk}]'):<30}  "
                  f"{p['port']}/{p['protocol']}  {p['service']}"
                  + (f"  —  {p.get('subcategory', '')}" if p.get('subcategory') else ""))

    print()
    print(_divider("═"))
