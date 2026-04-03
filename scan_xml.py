# scan_xml.py
# Part of: Nmap Recon Analyzer
# Parses Nmap XML scan output into structured host/port data.

import xml.etree.ElementTree as ET

def parse_host(host_elem) -> dict | None:
    """Extract IP address and open ports from a single <host> element."""
    # Pull the IP address from the <address> element
    addr_elem = host_elem.find("address[@addrtype='ipv4']")
    if addr_elem is None:
        return None # Skip hosts with no IPv4 address
    ip = addr_elem.get("addr", "unknown")
    ports = parse_ports(host_elem)
    return {"ip": ip, "ports": ports}

def parse_ports(host_elem) -> list[dict]:
    """Extract open ports from a <host> element."""
    open_ports = []
    for port_elem in host_elem.findall(".//port"):
         port_num = int(port_elem.get("portid", 0))
         protocol = port_elem.get("protocol", "tcp")
         # Use service name if available, otherwise fall back to "unknown"
         service_elem = port_elem.find("service")
         service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
         open_ports.append({
             "port": port_num,
             "protocol": protocol,
             "service": service,
        })
    return open_ports
def parse_scan(file_path: str) -> list[dict]:
    """
    Parse an Nmap XML file and return a list of hosts with their open ports.
    Returns an empty list if the file cannot be parsed.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[ERROR] Failed to parse XML: {e}")
        return []
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return []
    hosts = []
    for host_elem in root.findall("host"):
        host = parse_host(host_elem)
        if host is not None:
            hosts.append(host)
    return hosts

if __name__ == "__main__":
    import json
    results = parse_scan("scan.xml")
    print(json.dumps(results, indent=2))
