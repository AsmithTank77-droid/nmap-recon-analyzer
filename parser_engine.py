import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    results = []

    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall("host"):
        address = host.find("address").get("addr")
        ports = host.find("ports")
        for port in ports.findall("port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state= port.find("state").get("state")
                results.append({
                    "ip": address,
                    "port": port_id,
                    "protocol": protocol,
                    "state": state
                })


    return results

    if __name__ == "__main__":
        data = parse_nmap_xml("scan.xml")
        for item in data:
            print(item)
