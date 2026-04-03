# risk_engine.py

def calculate_risk(port):

    port = int(port)

    if port in [22,3389]:
        return "High"

    elif port in [21,23]:
        return "Critical"

    elif port in [80,443]:
        return "Medium"

    elif port in [445,139]:
        return "High"

    else:
        return "Low"

def process_all_hosts(hosts):
    """Assess risk for each port on each host."""
    results = []
    for host in hosts:
        host_result = {
            "ip": host["ip"],
            "ports": []
        }
        for port in host["ports"]:
            risk = calculate_risk(port["port"])
            host_result["ports"].append({
                "port": port["port"],
                "protocol": port["protocol"],
                "service": port["service"],
                "risk": risk
            })
        results.append(host_result)
    return results

def summary_report(results):
    """Print a summary of hosts and their risk levels."""
    for host in results:
        print(f"\nHost: {host['ip']}")
        for port in host["ports"]:
            print(f"  Port {port['port']}/{port['protocol']} ({port['service']}) - Risk: {port['risk']}")

