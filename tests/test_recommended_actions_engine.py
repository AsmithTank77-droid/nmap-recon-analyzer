"""
Tests for recommended_actions_engine.py — SOC recommended actions generator.
"""
import pytest
from recommended_actions_engine import generate_recommendations, _build_recommendation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _host(ip, ports):
    """Build a minimal host dict in the risk_scoring.py output shape."""
    return {"host": ip, "risk_level": "High", "ports": ports}


def _port(port, service, risk="High", state="open", protocol="tcp"):
    return {
        "port":      port,
        "protocol":  protocol,
        "service":   service,
        "state":     state,
        "risk":      risk,
        "risk_flags": [],
    }


# ---------------------------------------------------------------------------
# generate_recommendations — top-level API
# ---------------------------------------------------------------------------

class TestGenerateRecommendations:
    def test_empty_input_returns_empty(self):
        assert generate_recommendations([]) == []

    def test_returns_one_result_per_host(self):
        hosts = [
            _host("10.0.0.1", [_port(22, "ssh")]),
            _host("10.0.0.2", [_port(3389, "rdp")]),
        ]
        results = generate_recommendations(hosts)
        assert len(results) == 2

    def test_ip_field_correct(self):
        hosts = [_host("192.168.1.50", [_port(22, "ssh")])]
        result = generate_recommendations(hosts)[0]
        assert result["ip"] == "192.168.1.50"

    def test_overall_risk_level_present(self):
        hosts = [_host("10.0.0.1", [_port(22, "ssh", risk="High")])]
        result = generate_recommendations(hosts)[0]
        assert result["overall_risk_level"] == "High"

    def test_overall_host_summary_nonempty(self):
        hosts = [_host("10.0.0.1", [_port(22, "ssh")])]
        result = generate_recommendations(hosts)[0]
        assert len(result["overall_host_summary"]) > 0

    def test_summary_contains_ip(self):
        hosts = [_host("10.0.0.1", [_port(22, "ssh")])]
        result = generate_recommendations(hosts)[0]
        assert "10.0.0.1" in result["overall_host_summary"]

    def test_recommendations_list_present(self):
        hosts = [_host("10.0.0.1", [_port(22, "ssh")])]
        result = generate_recommendations(hosts)[0]
        assert "recommendations" in result
        assert isinstance(result["recommendations"], list)

    def test_one_recommendation_per_open_port(self):
        hosts = [_host("10.0.0.1", [
            _port(22,   "ssh"),
            _port(80,   "http"),
            _port(3389, "rdp"),
        ])]
        result = generate_recommendations(hosts)[0]
        assert len(result["recommendations"]) == 3

    def test_filtered_ports_excluded(self):
        hosts = [_host("10.0.0.1", [
            _port(22,  "ssh",  state="open"),
            _port(445, "smb",  state="filtered"),
        ])]
        result = generate_recommendations(hosts)[0]
        assert len(result["recommendations"]) == 1
        assert result["recommendations"][0]["port"] == 22

    def test_closed_ports_excluded(self):
        hosts = [_host("10.0.0.1", [
            _port(22, "ssh",  state="open"),
            _port(80, "http", state="closed"),
        ])]
        result = generate_recommendations(hosts)[0]
        assert len(result["recommendations"]) == 1

    def test_sorted_by_priority_then_port(self):
        hosts = [_host("10.0.0.1", [
            _port(80,   "http",   risk="Medium"),
            _port(3389, "rdp",    risk="Critical"),
            _port(22,   "ssh",    risk="Medium"),
        ])]
        recs = generate_recommendations(hosts)[0]["recommendations"]
        priorities = [r["priority"] for r in recs]
        assert priorities == sorted(priorities)

    def test_host_with_no_ports_returns_empty_recommendations(self):
        hosts = [_host("10.0.0.1", [])]
        result = generate_recommendations(hosts)[0]
        assert result["recommendations"] == []

    def test_accepts_risk_scoring_host_key(self):
        host = {"host": "10.0.0.1", "risk_level": "High", "ports": [_port(22, "ssh")]}
        result = generate_recommendations([host])[0]
        assert result["ip"] == "10.0.0.1"

    def test_accepts_ip_key(self):
        host = {"ip": "10.0.0.2", "ports": [_port(22, "ssh")]}
        result = generate_recommendations([host])[0]
        assert result["ip"] == "10.0.0.2"


# ---------------------------------------------------------------------------
# generate_recommendations — recommendation record schema
# ---------------------------------------------------------------------------

class TestRecommendationSchema:
    _REQUIRED_KEYS = {
        "port", "protocol", "service", "category", "subcategory",
        "risk_level", "priority", "service_context", "risk_rationale",
        "action_taken", "enumeration_steps", "hardening_checks",
        "notable_cves", "flags",
    }

    def _get_recs(self, port_num, service, risk="High"):
        hosts = [_host("10.0.0.1", [_port(port_num, service, risk=risk)])]
        return generate_recommendations(hosts)[0]["recommendations"]

    def test_all_required_keys_present(self):
        recs = self._get_recs(22, "ssh")
        assert self._REQUIRED_KEYS.issubset(recs[0].keys())

    def test_priority_is_integer(self):
        recs = self._get_recs(22, "ssh")
        assert isinstance(recs[0]["priority"], int)

    def test_priority_range(self):
        for risk, expected_p in [("Critical", 1), ("High", 2), ("Medium", 3),
                                  ("Low", 4), ("Informational", 5)]:
            recs = self._get_recs(22, "ssh", risk=risk)
            assert recs[0]["priority"] == expected_p, f"Priority wrong for {risk}"

    def test_service_context_nonempty(self):
        recs = self._get_recs(3389, "rdp")
        assert len(recs[0]["service_context"]) > 0

    def test_risk_rationale_nonempty(self):
        recs = self._get_recs(22, "ssh", risk="Critical")
        assert len(recs[0]["risk_rationale"]) > 0

    def test_action_taken_nonempty(self):
        recs = self._get_recs(22, "ssh")
        assert len(recs[0]["action_taken"]) > 0

    def test_action_taken_varies_by_risk_level(self):
        hosts_low  = [_host("10.0.0.1", [_port(22, "ssh", risk="Low")])]
        hosts_crit = [_host("10.0.0.1", [_port(22, "ssh", risk="Critical")])]
        action_low  = generate_recommendations(hosts_low)[0]["recommendations"][0]["action_taken"]
        action_crit = generate_recommendations(hosts_crit)[0]["recommendations"][0]["action_taken"]
        assert action_low != action_crit

    def test_enumeration_steps_are_list(self):
        recs = self._get_recs(22, "ssh")
        assert isinstance(recs[0]["enumeration_steps"], list)

    def test_enumeration_steps_have_required_fields(self):
        recs = self._get_recs(22, "ssh", risk="High")
        for step in recs[0]["enumeration_steps"]:
            assert "step"    in step
            assert "tool"    in step
            assert "command" in step
            assert "purpose" in step

    def test_enumeration_steps_numbered_sequentially(self):
        recs = self._get_recs(445, "smb", risk="High")
        steps = recs[0]["enumeration_steps"]
        numbers = [s["step"] for s in steps]
        assert numbers == list(range(1, len(steps) + 1))

    def test_enum_commands_contain_real_ip(self):
        hosts = [_host("192.168.99.1", [_port(3389, "rdp", risk="Critical")])]
        recs  = generate_recommendations(hosts)[0]["recommendations"]
        for step in recs[0]["enumeration_steps"]:
            assert "192.168.99.1" in step["command"]

    def test_enum_commands_contain_real_port(self):
        hosts = [_host("10.0.0.1", [_port(2222, "ssh", risk="High")])]
        recs  = generate_recommendations(hosts)[0]["recommendations"]
        for step in recs[0]["enumeration_steps"]:
            assert "2222" in step["command"]

    def test_hardening_checks_nonempty_for_known_service(self):
        recs = self._get_recs(3389, "rdp")
        assert len(recs[0]["hardening_checks"]) > 0

    def test_notable_cves_for_cve_prone_service(self):
        recs = self._get_recs(3389, "rdp")
        assert len(recs[0]["notable_cves"]) > 0

    def test_category_field_correct(self):
        recs = self._get_recs(22, "ssh")
        assert recs[0]["category"] == "Remote Access"


# ---------------------------------------------------------------------------
# generate_recommendations — service alias resolution
# ---------------------------------------------------------------------------

class TestAliasResolution:
    def test_microsoft_ds_resolves_to_smb(self):
        hosts = [_host("10.0.0.1", [_port(445, "microsoft-ds")])]
        recs  = generate_recommendations(hosts)[0]["recommendations"]
        assert recs[0]["service"] == "smb"

    def test_ms_wbt_server_resolves_to_rdp(self):
        hosts = [_host("10.0.0.1", [_port(3389, "ms-wbt-server")])]
        recs  = generate_recommendations(hosts)[0]["recommendations"]
        assert recs[0]["service"] == "rdp"


# ---------------------------------------------------------------------------
# generate_recommendations — multi-host scenarios
# ---------------------------------------------------------------------------

class TestMultiHost:
    def test_each_host_gets_independent_report(self):
        hosts = [
            _host("10.0.0.1", [_port(22,   "ssh",  risk="Low")]),
            _host("10.0.0.2", [_port(3389, "rdp",  risk="Critical")]),
        ]
        results = generate_recommendations(hosts)
        ips = [r["ip"] for r in results]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_recommendations_not_shared_between_hosts(self):
        hosts = [
            _host("10.0.0.1", [_port(22,   "ssh")]),
            _host("10.0.0.2", [_port(3389, "rdp")]),
        ]
        results = generate_recommendations(hosts)
        h1_services = {r["service"] for r in results[0]["recommendations"]}
        h2_services = {r["service"] for r in results[1]["recommendations"]}
        assert h1_services != h2_services
