def format_output(analyzed_results, suggestions):
    print("\n" + "="*60)
    print("       NMAP RECON ANALYZER - SOC REPORT")
    print("="*60)
    print(f"{'PORT':<8} {'PROTOCOL':<10} {'SERVICE':<18} {'RISK':<10}")
    print("-"*60)

    for entry in analyzed_results:
        print(f"{str(entry['port']):<8} {str(entry['protocol']):<10} {str(entry['service']):<18} {str(entry['risk']):<10}")

    print("="*60)
    print("\nSUGGESTED ENUMERATION COMMANDS:")
    print("-"*60)

    for entry in suggestions:
        if entry['risk'] in ['Critical', 'High', 'Medium']:
            print(f"\nPort {entry['port']} ({entry['service']}):")
            for cmd in entry['enum']:
                print(f"  -> {cmd}")

    print("\n" + "="*60)
