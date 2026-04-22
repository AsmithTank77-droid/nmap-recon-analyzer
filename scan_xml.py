# scan_xml.py
# Part of: nmap-recon-analyzer
# Parses Nmap XML scan output into structured host/port data.

import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


def _get_ip(host_elem) -> str | None:
    """Return the best available IP address for a host element (IPv4 preferred)."""
    for addrtype in ("ipv4", "ipv6"):
        elem = host_elem.find(f"address[@addrtype='{addrtype}']")
        if elem is not None:
            return elem.get("addr")
    return None


def _parse_ports(host_elem) -> list[dict]:
    """Extract all ports from a <host> element regardless of state."""
    ports = []
    for port_elem in host_elem.findall(".//port"):
        port_num = int(port_elem.get("portid", 0))
        protocol = port_elem.get("protocol", "tcp")

        service_elem = port_elem.find("service")
        service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

        state_elem = port_elem.find("state")
        state = state_elem.get("state", "open") if state_elem is not None else "open"

        ports.append({
            "port":     port_num,
            "protocol": protocol,
            "service":  service,
            "state":    state,
        })
    return ports


def _parse_host(host_elem) -> dict | None:
    """Extract IP address and ports from a single <host> element."""
    ip = _get_ip(host_elem)
    if ip is None:
        logger.debug("Skipping host element with no IP address.")
        return None
    return {"ip": ip, "ports": _parse_ports(host_elem)}


def parse_scan(file_path: str) -> list[dict]:
    """
    Parse an Nmap XML file and return a list of hosts with their ports.

    Each host dict: {"ip": str, "ports": list[dict]}
    Each port dict: {"port": int, "protocol": str, "service": str, "state": str}

    Returns an empty list if the file cannot be parsed.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.error("Failed to parse XML: %s", exc)
        return []
    except FileNotFoundError:
        logger.error("Scan file not found: %s", file_path)
        return []

    hosts = []
    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host is not None:
            hosts.append(host)

    logger.debug("parse_scan: found %d host(s) in %s", len(hosts), file_path)
    return hosts


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    results = parse_scan("scan.xml")
    print(json.dumps(results, indent=2))
