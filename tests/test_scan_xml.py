"""
Tests for scan_xml.py — the Nmap XML parser.
"""
import pytest
from scan_xml import parse_scan


# ---------------------------------------------------------------------------
# XML fixtures
# ---------------------------------------------------------------------------

_SINGLE_HOST = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="filtered"/>
        <service name="smb"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_TWO_HOSTS = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="rdp"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_IPV6_ONLY = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NO_SERVICE_NAME = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NO_STATE = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NO_ADDRESS = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_EMPTY_NMAPRUN = '<?xml version="1.0"?><nmaprun></nmaprun>'

_MIXED_STATES = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="filtered"/>
        <service name="smb"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def xml_file(tmp_path):
    """Factory: write XML content to a temp file and return the path."""
    def _make(content: str) -> str:
        f = tmp_path / "scan.xml"
        f.write_text(content, encoding="utf-8")
        return str(f)
    return _make


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------

class TestParseSingleHost:
    def test_returns_one_host(self, xml_file):
        hosts = parse_scan(xml_file(_SINGLE_HOST))
        assert len(hosts) == 1

    def test_ip_address_correct(self, xml_file):
        hosts = parse_scan(xml_file(_SINGLE_HOST))
        assert hosts[0]["ip"] == "192.168.1.1"

    def test_all_ports_returned(self, xml_file):
        hosts = parse_scan(xml_file(_SINGLE_HOST))
        assert len(hosts[0]["ports"]) == 3

    def test_port_fields_correct(self, xml_file):
        hosts = parse_scan(xml_file(_SINGLE_HOST))
        ssh = next(p for p in hosts[0]["ports"] if p["port"] == 22)
        assert ssh["service"]  == "ssh"
        assert ssh["state"]    == "open"
        assert ssh["protocol"] == "tcp"
        assert ssh["port"]     == 22

    def test_filtered_port_included(self, xml_file):
        hosts  = parse_scan(xml_file(_SINGLE_HOST))
        states = {p["state"] for p in hosts[0]["ports"]}
        assert "filtered" in states


class TestParseTwoHosts:
    def test_returns_two_hosts(self, xml_file):
        hosts = parse_scan(xml_file(_TWO_HOSTS))
        assert len(hosts) == 2

    def test_both_ips_present(self, xml_file):
        hosts = parse_scan(xml_file(_TWO_HOSTS))
        ips   = {h["ip"] for h in hosts}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_each_host_has_correct_port(self, xml_file):
        hosts = parse_scan(xml_file(_TWO_HOSTS))
        by_ip = {h["ip"]: h for h in hosts}
        assert by_ip["10.0.0.1"]["ports"][0]["service"] == "ssh"
        assert by_ip["10.0.0.2"]["ports"][0]["service"] == "rdp"


# ---------------------------------------------------------------------------
# IPv6 fallback
# ---------------------------------------------------------------------------

class TestIPv6Fallback:
    def test_ipv6_address_parsed(self, xml_file):
        hosts = parse_scan(xml_file(_IPV6_ONLY))
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "2001:db8::1"

    def test_ipv6_port_parsed(self, xml_file):
        hosts = parse_scan(xml_file(_IPV6_ONLY))
        assert hosts[0]["ports"][0]["port"] == 22


# ---------------------------------------------------------------------------
# Missing or absent optional fields
# ---------------------------------------------------------------------------

class TestMissingFields:
    def test_missing_service_name_defaults_to_unknown(self, xml_file):
        hosts = parse_scan(xml_file(_NO_SERVICE_NAME))
        assert hosts[0]["ports"][0]["service"] == "unknown"

    def test_missing_state_defaults_to_open(self, xml_file):
        hosts = parse_scan(xml_file(_NO_STATE))
        assert hosts[0]["ports"][0]["state"] == "open"

    def test_host_with_no_address_skipped(self, xml_file):
        hosts = parse_scan(xml_file(_NO_ADDRESS))
        assert hosts == []


# ---------------------------------------------------------------------------
# Mixed port states — all states returned
# ---------------------------------------------------------------------------

class TestMixedStates:
    def test_all_three_states_present(self, xml_file):
        hosts  = parse_scan(xml_file(_MIXED_STATES))
        states = {p["state"] for p in hosts[0]["ports"]}
        assert states == {"open", "closed", "filtered"}

    def test_correct_port_count(self, xml_file):
        hosts = parse_scan(xml_file(_MIXED_STATES))
        assert len(hosts[0]["ports"]) == 3


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_file_not_found_returns_empty(self):
        result = parse_scan("/nonexistent/path/scan.xml")
        assert result == []

    def test_malformed_xml_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("this is not xml <<<>>>", encoding="utf-8")
        result = parse_scan(str(bad))
        assert result == []

    def test_empty_nmaprun_returns_empty(self, xml_file):
        result = parse_scan(xml_file(_EMPTY_NMAPRUN))
        assert result == []

    def test_does_not_raise_on_bad_input(self):
        try:
            parse_scan("/dev/null")
        except Exception as exc:
            pytest.fail(f"parse_scan raised unexpectedly: {exc}")
