from parser_engine import parse_nmap_xml
from classifier import classify_service
from risk_engine import calculate_risk
from enum_suggestions import suggest_enum
from formatter import format_output

def main():
    results = parse_nmap_xml("scan.xml")
    analyzed_results = []

    for entry in results:
        service = classify_service(entry["port"])
        risk = calculate_risk(entry["port"])
        enum_cmd = suggest_enum(entry["port"], service)

        entry["service"] = service
        entry["risk"] = risk
        entry["enum"] = enum_cmd

        analyzed_results.append(entry)

    suggestions = analyzed_results
    format_output(analyzed_results, suggestions)

if __name__ == "__main__":
    main()