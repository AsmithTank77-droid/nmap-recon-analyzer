"""
Tests for risk_scoring.py — the four-component scoring engine.
"""
import pytest
from risk_scoring import (
    _risk_level,
    _port_risk_label,
    score_port,
    score_host,
    process_all_hosts,
    _score_service_risk,
    _score_exposure_risk,
    _score_attack_surface,
    _score_threat_context,
)


# ---------------------------------------------------------------------------
# _risk_level — composite score → severity label
# ---------------------------------------------------------------------------

class TestRiskLevel:
    def test_critical_at_threshold(self):
        assert _risk_level(75) == "Critical"

    def test_critical_above_threshold(self):
        assert _risk_level(100) == "Critical"

    def test_high_at_threshold(self):
        assert _risk_level(55) == "High"

    def test_high_just_below_critical(self):
        assert _risk_level(74) == "High"

    def test_medium_at_threshold(self):
        assert _risk_level(35) == "Medium"

    def test_medium_just_below_high(self):
        assert _risk_level(54) == "Medium"

    def test_low_at_threshold(self):
        assert _risk_level(15) == "Low"

    def test_low_just_below_medium(self):
        assert _risk_level(34) == "Low"

    def test_informational_at_zero(self):
        assert _risk_level(0) == "Informational"

    def test_informational_just_below_low(self):
        assert _risk_level(14) == "Informational"


# ---------------------------------------------------------------------------
# _port_risk_label — weighted score → per-port risk label
# ---------------------------------------------------------------------------

class TestPortRiskLabel:
    def test_critical_at_8(self):
        assert _port_risk_label(8.0) == "Critical"

    def test_high_at_6(self):
        assert _port_risk_label(6.0) == "High"

    def test_medium_at_4(self):
        assert _port_risk_label(4.0) == "Medium"

    def test_low_at_2(self):
        assert _port_risk_label(2.0) == "Low"

    def test_informational_below_2(self):
        assert _port_risk_label(1.9) == "Informational"
        assert _port_risk_label(0.0) == "Informational"


# ---------------------------------------------------------------------------
# score_port — single port scoring
# ---------------------------------------------------------------------------

class TestScorePort:
    def test_rdp_open_is_critical(self):
        p = score_port({"port": 3389, "protocol": "tcp", "service": "rdp", "state": "open"})
        assert p.risk_label == "Critical"
        assert p.weighted_score >= 8.0

    def test_telnet_open_is_critical(self):
        p = score_port({"port": 23, "protocol": "tcp", "service": "telnet", "state": "open"})
        assert p.risk_label == "Critical"

    def test_smb_open_is_high(self):
        p = score_port({"port": 445, "protocol": "tcp", "service": "smb", "state": "open"})
        assert p.risk_label in ("Critical", "High")

    def test_ssh_open_is_medium(self):
        p = score_port({"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"})
        assert p.risk_label == "Medium"

    def test_filtered_reduces_weighted_score(self):
        open_p     = score_port({"port": 445, "service": "smb", "state": "open"})
        filtered_p = score_port({"port": 445, "service": "smb", "state": "filtered"})
        assert filtered_p.weighted_score < open_p.weighted_score

    def test_closed_has_lowest_weighted_score(self):
        open_p   = score_port({"port": 22, "service": "ssh", "state": "open"})
        closed_p = score_port({"port": 22, "service": "ssh", "state": "closed"})
        assert closed_p.weighted_score < open_p.weighted_score

    def test_high_risk_port_flag_attached(self):
        p = score_port({"port": 3389, "service": "rdp", "state": "open"})
        assert any("well-known-risky-port" in f for f in p.flags)

    def test_unknown_service_returns_valid_result(self):
        p = score_port({"port": 9999, "service": "unknown", "state": "open"})
        assert p.risk_label in ("Critical", "High", "Medium", "Low", "Informational")
        assert p.weighted_score >= 0

    def test_port_fields_populated(self):
        p = score_port({"port": 80, "protocol": "tcp", "service": "http", "state": "open"})
        assert p.port == 80
        assert p.protocol == "tcp"
        assert p.service == "http"
        assert p.state == "open"


# ---------------------------------------------------------------------------
# _score_service_risk — component 1 (max 40)
# ---------------------------------------------------------------------------

class TestScoreServiceRisk:
    def test_empty_ports_returns_zero(self):
        pts, _, _ = _score_service_risk([])
        assert pts == 0

    def test_high_risk_service_scores_high(self):
        open_ports = [score_port({"port": 3389, "service": "rdp", "state": "open"})]
        pts, _, _ = _score_service_risk(open_ports)
        assert pts > 20

    def test_does_not_exceed_maximum(self):
        open_ports = [
            score_port({"port": 3389, "service": "rdp",    "state": "open"}),
            score_port({"port": 23,   "service": "telnet", "state": "open"}),
            score_port({"port": 5900, "service": "vnc",    "state": "open"}),
            score_port({"port": 445,  "service": "smb",    "state": "open"}),
            score_port({"port": 3306, "service": "mysql",  "state": "open"}),
        ]
        pts, _, _ = _score_service_risk(open_ports)
        assert pts <= 40

    def test_reasoning_names_highest_risk_service(self):
        open_ports = [
            score_port({"port": 3389, "service": "rdp", "state": "open"}),
            score_port({"port": 22,   "service": "ssh", "state": "open"}),
        ]
        _, _, reasons = _score_service_risk(open_ports)
        assert any("rdp" in r.lower() for r in reasons)


# ---------------------------------------------------------------------------
# _score_exposure_risk — component 2 (max 25)
# ---------------------------------------------------------------------------

class TestScoreExposureRisk:
    def test_zero_open_ports_returns_zero(self):
        pts, _, _ = _score_exposure_risk([], [])
        assert pts == 0

    def test_many_open_ports_scores_higher_than_few(self):
        few_raw   = [{"port": 22,  "service": "ssh",  "state": "open"}]
        many_raw  = [{"port": i,   "service": "http", "state": "open"} for i in range(15)]
        few_open  = [score_port(p) for p in few_raw]
        many_open = [score_port(p) for p in many_raw]
        few_pts,  _, _ = _score_exposure_risk(few_raw,  few_open)
        many_pts, _, _ = _score_exposure_risk(many_raw, many_open)
        assert many_pts > few_pts

    def test_does_not_exceed_maximum(self):
        raw   = [{"port": i, "service": "http", "state": "open"} for i in range(20)]
        open_ = [score_port(p) for p in raw]
        pts, _, _ = _score_exposure_risk(raw, open_)
        assert pts <= 25

    def test_filtered_high_risk_port_adds_points(self):
        raw_with    = [{"port": 445, "service": "smb", "state": "filtered"}]
        raw_without = []
        pts_with,    _, _ = _score_exposure_risk(raw_with,    [])
        pts_without, _, _ = _score_exposure_risk(raw_without, [])
        assert pts_with > pts_without


# ---------------------------------------------------------------------------
# _score_attack_surface — component 3 (max 20)
# ---------------------------------------------------------------------------

class TestScoreAttackSurface:
    def test_no_dangerous_services_returns_zero(self):
        open_ports = [
            score_port({"port": 22, "service": "ssh",  "state": "open"}),
            score_port({"port": 80, "service": "http", "state": "open"}),
        ]
        pts, _, _ = _score_attack_surface(open_ports)
        assert pts == 0

    def test_smb_rdp_combo_detected(self):
        open_ports = [
            score_port({"port": 445,  "service": "smb", "state": "open"}),
            score_port({"port": 3389, "service": "rdp", "state": "open"}),
        ]
        pts, _, reasons = _score_attack_surface(open_ports)
        assert pts >= 5
        assert any("SMB" in r or "smb" in r.lower() for r in reasons)

    def test_concentration_bonus_at_three_dangerous_services(self):
        open_ports = [
            score_port({"port": 3389, "service": "rdp",   "state": "open"}),
            score_port({"port": 445,  "service": "smb",   "state": "open"}),
            score_port({"port": 3306, "service": "mysql", "state": "open"}),
        ]
        _, _, reasons = _score_attack_surface(open_ports)
        assert any("dangerous" in r.lower() for r in reasons)

    def test_does_not_exceed_maximum(self):
        open_ports = [
            score_port({"port": 3389, "service": "rdp",    "state": "open"}),
            score_port({"port": 445,  "service": "smb",    "state": "open"}),
            score_port({"port": 23,   "service": "telnet", "state": "open"}),
            score_port({"port": 3306, "service": "mysql",  "state": "open"}),
            score_port({"port": 5900, "service": "vnc",    "state": "open"}),
            score_port({"port": 21,   "service": "ftp",    "state": "open"}),
        ]
        pts, _, _ = _score_attack_surface(open_ports)
        assert pts <= 20


# ---------------------------------------------------------------------------
# _score_threat_context — component 4 (max 15)
# ---------------------------------------------------------------------------

class TestScoreThreatContext:
    def test_no_context_returns_zero(self):
        pts, _, _ = _score_threat_context(None)
        assert pts == 0

    def test_empty_signals_returns_zero(self):
        pts, _, _ = _score_threat_context({"signals": [], "geo_info": {}})
        assert pts == 0

    def test_proxy_signal_adds_eight_points(self):
        ctx = {"signals": ["IP identified as proxy, VPN, or Tor exit node."], "geo_info": {}}
        pts, _, reasons = _score_threat_context(ctx)
        assert pts == 8
        assert any("proxy" in r.lower() or "vpn" in r.lower() for r in reasons)

    def test_datacenter_signal_adds_five_points(self):
        ctx = {"signals": ["IP is hosted in a commercial data center / cloud provider."], "geo_info": {}}
        pts, _, _ = _score_threat_context(ctx)
        assert pts == 5

    def test_high_risk_country_adds_five_points(self):
        ctx = {
            "signals": ["IP originates from Russia — elevated-risk country per public threat intel feeds."],
            "geo_info": {"country": "Russia"},
        }
        pts, _, _ = _score_threat_context(ctx)
        assert pts == 5

    def test_does_not_exceed_maximum(self):
        ctx = {
            "signals": [
                "IP identified as proxy, VPN, or Tor exit node.",
                "IP is hosted in a commercial data center / cloud provider.",
                "IP originates from Russia — elevated-risk country.",
                "IP belongs to a mobile / cellular carrier.",
            ],
            "geo_info": {"country": "Russia"},
        }
        pts, _, _ = _score_threat_context(ctx)
        assert pts <= 15


# ---------------------------------------------------------------------------
# score_host — full host scoring integration
# ---------------------------------------------------------------------------

class TestScoreHost:
    def test_no_ports_returns_informational(self):
        result = score_host({"host": "10.0.0.1", "ports": []})
        assert result.total_score == 0
        assert result.risk_level == "Informational"

    def test_all_closed_ports_low_score(self):
        result = score_host({"host": "10.0.0.1", "ports": [
            {"port": 22,  "service": "ssh",  "state": "closed"},
            {"port": 80,  "service": "http", "state": "closed"},
            {"port": 443, "service": "https","state": "closed"},
        ]})
        assert result.total_score < 15

    def test_high_risk_host_scores_above_medium_threshold(self):
        result = score_host({"host": "10.0.0.1", "ports": [
            {"port": 3389, "service": "rdp", "state": "open"},
            {"port": 445,  "service": "smb", "state": "open"},
        ]})
        assert result.total_score >= 35

    def test_breakdown_keys_present(self):
        result = score_host({"host": "10.0.0.1", "ports": [
            {"port": 22, "service": "ssh", "state": "open"},
        ]})
        assert set(result.breakdown.keys()) == {
            "service_risk", "exposure_risk", "attack_surface", "threat_context"
        }

    def test_total_score_equals_sum_of_components(self):
        result = score_host({"host": "10.0.0.1", "ports": [
            {"port": 22,  "service": "ssh",  "state": "open"},
            {"port": 80,  "service": "http", "state": "open"},
            {"port": 445, "service": "smb",  "state": "open"},
        ]})
        component_sum = sum(c.score for c in result.breakdown.values())
        assert result.total_score == component_sum

    def test_reasoning_list_nonempty_for_open_ports(self):
        result = score_host({"host": "10.0.0.1", "ports": [
            {"port": 22, "service": "ssh", "state": "open"},
        ]})
        assert len(result.reasoning) > 0

    def test_backward_compat_fields_present(self):
        result = score_host({"host": "10.0.0.1", "ports": [
            {"port": 22, "service": "ssh", "state": "open"},
        ]})
        assert hasattr(result, "composite_score")
        assert hasattr(result, "severity")
        assert hasattr(result, "risk_flags")


# ---------------------------------------------------------------------------
# process_all_hosts — pipeline entry point
# ---------------------------------------------------------------------------

class TestProcessAllHosts:
    def test_empty_input_returns_empty(self):
        assert process_all_hosts([]) == []

    def test_results_sorted_highest_score_first(self):
        hosts = [
            {"host": "1.1.1.1", "ports": [
                {"port": 22, "service": "ssh", "state": "open"},
            ]},
            {"host": "2.2.2.2", "ports": [
                {"port": 3389, "service": "rdp",  "state": "open"},
                {"port": 445,  "service": "smb",  "state": "open"},
                {"port": 23,   "service": "telnet","state": "open"},
            ]},
        ]
        results = process_all_hosts(hosts)
        assert results[0].total_score >= results[1].total_score

    def test_all_hosts_present_in_output(self):
        hosts = [
            {"host": "10.0.0.1", "ports": [{"port": 22, "service": "ssh", "state": "open"}]},
            {"host": "10.0.0.2", "ports": [{"port": 80, "service": "http","state": "open"}]},
            {"host": "10.0.0.3", "ports": [{"port": 443,"service": "https","state":"open"}]},
        ]
        results = process_all_hosts(hosts)
        assert len(results) == 3

    def test_ip_context_fed_to_threat_component(self):
        hosts = [{"host": "10.0.0.1", "ports": [
            {"port": 22, "service": "ssh", "state": "open"},
        ]}]
        ctx = {"10.0.0.1": {
            "signals":  ["IP identified as proxy, VPN, or Tor exit node."],
            "geo_info": {},
        }}
        with_ctx    = process_all_hosts(hosts, ip_contexts=ctx)
        without_ctx = process_all_hosts(hosts)
        assert with_ctx[0].breakdown["threat_context"].score > \
               without_ctx[0].breakdown["threat_context"].score
