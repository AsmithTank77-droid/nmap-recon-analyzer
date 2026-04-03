# analyzer.py
# Part of: nmap-recon-analyzer
# Main entry point — orchestrates parsing, classification, risk scoring,
# enumeration suggestions, and formatted output.
from scan_xml import parse_scan
from classifier import classify_service
from risk_engine import process_all_hosts, summary_report
from enum_suggestions import suggest_enum
from formatter import format_output
def main():
    # 1. Parse the Nmap XML scan file
    raw_hosts = parse_scan("scan.xml")

    if not raw_hosts:
        print("[!] No hosts found in scan.xml")
        return

    # 2. Run risk engine across all hosts (sorted by composite score)
    host_risks = process_all_hosts(raw_hosts)

    # 3. Build flat analyzed_results list for formatter/enum (per-port view)
    analyzed_results = []
    for hr in host_risks:
        for p in hr["ports"]:
            service_category = classify_service(p["port"])
            enum_cmds = suggest_enum(p["port"], service_category)
            analyzed_results.append({
                "host": hr["ip"],
                "port": p["port"],
                "protocol": p["protocol"],
                "service": p["service"],
                "risk": p["risk"],
                "enum": enum_cmds,
            })

    # 4. Print risk engine summary
    summary_report(host_risks)

    # 5. Print SOC-style formatted output with enum suggestions
    format_output(analyzed_results, analyzed_results)


if __name__ == "__main__":
    main()
