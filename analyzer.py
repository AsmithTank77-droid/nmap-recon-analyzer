import json
import logging
from datetime import datetime, timezone

from scan_xml import parse_scan
import service_intelligence as si
from risk_scoring import process_all_hosts, summary_report, _host_to_threat_services
from threat_context import generate_threat_insights, pretty_print_insights, analyze_ip
from recommended_actions_engine import generate_recommendations
from formatter import format_output, format_recommended_actions

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run(scan_file, output_path="risk_report.json", quiet=False):

    _log = (lambda *a, **k: None) if quiet else print

    # ------------------------------------------------------------------
    # STEP 1 — PARSE
    # scan_xml returns: [{ip, ports: [{port, protocol, service, state}]}]
    # ------------------------------------------------------------------
    _log("\n[1/6] Parsing scan file...")
    raw_hosts = parse_scan(scan_file)
    if not raw_hosts:
        _log("[!] No hosts found in scan file.")
        return
    logger.info("Parsed %d host(s).", len(raw_hosts))

    # ------------------------------------------------------------------
    # STEP 2 — CLASSIFY
    # Validate that every port can be resolved to a known service category.
    # Full intelligence (gated enum commands, CVEs, hardening checks) is
    # attached in Step 5 once the risk label is known.
    # ------------------------------------------------------------------
    _log("[2/6] Classifying services...")

    # ------------------------------------------------------------------
    # STEP 3 — RISK ENGINE
    # Fetch IP context first so the engine can score all four components
    # (service_risk, exposure_risk, attack_surface, threat_context).
    # risk_scoring expects "host" key; scan_xml uses "ip" — remap here.
    # ------------------------------------------------------------------
    _log("[3/6] Running risk engine...")
    ip_contexts = {h["ip"]: analyze_ip(h["ip"]) for h in raw_hosts}
    hosts       = [{"host": h["ip"], "ports": h["ports"]} for h in raw_hosts]
    results     = process_all_hosts(hosts, ip_contexts)
    _log(summary_report(results))

    # ------------------------------------------------------------------
    # STEP 4 — THREAT CONTEXT
    # Index insights by port number so the assembler can attach them
    # inline to each port entry without another loop.
    # ------------------------------------------------------------------
    _log("[4/6] Enriching with threat context...")
    threat_map = {}
    _log("\n" + "=" * 60)
    _log("  THREAT CONTEXT ANALYSIS")
    _log("=" * 60)
    for hr in results:
        services        = _host_to_threat_services(hr)
        insights, hvt   = generate_threat_insights(services)
        per_port_threat = {
            i["port"]: {"threat": i["threat"], "flags": i["flags"]}
            for i in insights
        }
        ip_ctx = ip_contexts.get(hr.host, {})
        threat_map[hr.host] = {
            "high_value_target": hvt,
            "per_port":          per_port_threat,
        }
        geo  = ip_ctx.get("geo_info", {})
        info = ip_ctx.get("ip_info",  {})
        _log(f"\n--- Host: {hr.host} ---")
        _log(f"  Location : {geo.get('city')}, {geo.get('country')}")
        _log(f"  Org      : {info.get('org')}")
        _log(f"  IP Risk  : {ip_ctx.get('risk')}")
        for sig in ip_ctx.get("signals", []):
            _log(f"  Signal   : {sig}")
        if not quiet:
            pretty_print_insights(insights, hvt)

    # ------------------------------------------------------------------
    # STEP 5 — FINAL ASSEMBLER
    # One pass per host/port — attach risk score, category, threat intel,
    # and enum suggestions together into a single complete record.
    # ------------------------------------------------------------------
    _log("\n[5/6] Assembling final report...")
    output = []

    for hr in results:
        threat_data     = threat_map.get(hr.host, {})
        per_port_threat = threat_data.get("per_port", {})

        ports_json = []

        for p in hr.ports:
            risk_label  = p.risk_label
            intel       = si.analyze(p.service, p.port, risk_label)
            port_threat = per_port_threat.get(p.port, {})

            ports_json.append({
                "port":               p.port,
                "protocol":           p.protocol,
                "service":            p.service,
                "state":              p.state,
                "category":           intel["category"],
                "subcategory":        intel["subcategory"],
                "protocol_cleartext": intel["protocol_cleartext"],
                "anonymous_risk":     intel["anonymous_risk"],
                "attack_phases":      intel["attack_phases"],
                "cve_prone":          intel["cve_prone"],
                "notable_cves":       intel["notable_cves"],
                "weighted_score":     p.weighted_score,
                "risk":               risk_label,
                "risk_flags":         p.flags,
                "threat":             port_threat.get("threat"),
                "threat_flags":       port_threat.get("flags", []),
                "hardening_checks":   intel["hardening_checks"],
                "enum_commands": [
                    {
                        "tool":    cmd["tool"],
                        "command": cmd["command"]
                                       .replace("{target}", hr.host)
                                       .replace("{port}", str(p.port)),
                        "purpose": cmd["purpose"],
                    }
                    for cmd in intel["enum_commands"]
                ],
            })

        _log(f"\n{'=' * 60}")
        _log(f"  SOC REPORT — {hr.host}")
        if not quiet:
            format_output(hr, ports_json)

        ip_ctx         = ip_contexts.get(hr.host, {})
        breakdown_json = {
            name: {
                "score":     comp.score,
                "max_score": comp.max_score,
                "detail":    comp.detail,
            }
            for name, comp in hr.breakdown.items()
        }
        output.append({
            "host":                 hr.host,
            "risk_level":           hr.risk_level,
            "total_score":          hr.total_score,
            "score_breakdown":      breakdown_json,
            "reasoning":            hr.reasoning,
            "structured_reasoning": hr.structured_reasoning,
            "high_value_target":    threat_data.get("high_value_target", False),
            "threat_context": {
                "ip_info":  ip_ctx.get("ip_info"),
                "geo_info": ip_ctx.get("geo_info"),
                "signals":  ip_ctx.get("signals", []),
                "risk":     ip_ctx.get("risk"),
            },
            "ports": ports_json,
        })

    # ------------------------------------------------------------------
    # STEP 6 — RECOMMENDED ACTIONS
    # Generate SOC recommended actions and embed in the JSON report.
    # The engine accepts the assembled output list directly.
    # ------------------------------------------------------------------
    _log("\n[6/6] Generating recommended actions...")
    recs = generate_recommendations(output)

    for host_data, rec in zip(output, recs):
        host_data["overall_host_summary"] = rec["overall_host_summary"]
        host_data["recommended_actions"]  = rec["recommendations"]
        if not quiet:
            format_recommended_actions(rec)

    # ------------------------------------------------------------------
    # EXPORT — risk_report.json
    # ------------------------------------------------------------------
    report = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_file":  scan_file,
            "host_count":   len(output),
            "analyzer":     "nmap-recon-analyzer",
        },
        "hosts": output,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("%s written (%d host(s)).", output_path, len(output))


def _build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog="nmap-recon-analyzer",
        description=(
            "Parse an Nmap XML scan and produce a SOC-style risk report with "
            "service intelligence, threat context, and recommended actions."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 analyzer.py scan.xml\n"
            "  python3 analyzer.py scan.xml --output results/report.json\n"
            "  python3 analyzer.py scan.xml --quiet\n"
        ),
    )
    p.add_argument(
        "scan_file",
        help="Path to the Nmap XML output file (nmap -oX scan.xml ...)",
    )
    p.add_argument(
        "--output", "-o",
        metavar="FILE",
        default="risk_report.json",
        help="Path for the JSON report output (default: risk_report.json)",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal output — write JSON report only",
    )
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    run(args.scan_file, output_path=args.output, quiet=args.quiet)
