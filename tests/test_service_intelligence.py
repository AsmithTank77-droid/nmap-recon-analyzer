"""
Tests for service_intelligence.py — the unified service knowledge base.
"""
import pytest
import service_intelligence as si


# ---------------------------------------------------------------------------
# classify — category string lookup
# ---------------------------------------------------------------------------

class TestClassify:
    def test_ssh_is_remote_access(self):
        assert si.classify("ssh", 22) == "Remote Access"

    def test_rdp_is_remote_access(self):
        assert si.classify("rdp", 3389) == "Remote Access"

    def test_http_is_web_service(self):
        assert si.classify("http", 80) == "Web Service"

    def test_https_is_web_service(self):
        assert si.classify("https", 443) == "Web Service"

    def test_mysql_is_database(self):
        assert si.classify("mysql", 3306) == "Database"

    def test_smb_is_file_sharing(self):
        assert si.classify("smb", 445) == "File Sharing"

    def test_smtp_is_email(self):
        assert si.classify("smtp", 25) == "Email Service"

    def test_snmp_is_infrastructure(self):
        assert si.classify("snmp", 161) == "Infrastructure"

    def test_ldap_is_directory(self):
        assert si.classify("ldap", 389) == "Directory Service"

    def test_unknown_service_unknown_port_is_unknown(self):
        assert si.classify("gibberish_xyz", 59999) == "Unknown"


# ---------------------------------------------------------------------------
# classify — alias resolution
# ---------------------------------------------------------------------------

class TestClassifyAliases:
    def test_microsoft_ds_resolves_to_smb(self):
        assert si.classify("microsoft-ds", 445) == "File Sharing"

    def test_ms_wbt_server_resolves_to_rdp(self):
        assert si.classify("ms-wbt-server", 3389) == "Remote Access"

    def test_ms_sql_s_resolves_to_mssql(self):
        assert si.classify("ms-sql-s", 1433) == "Database"

    def test_imaps_resolves_to_imap(self):
        assert si.classify("imaps", 993) == "Email Service"

    def test_submission_resolves_to_smtp(self):
        assert si.classify("submission", 587) == "Email Service"


# ---------------------------------------------------------------------------
# classify — port number fallback
# ---------------------------------------------------------------------------

class TestClassifyPortFallback:
    def test_unknown_service_name_falls_back_on_port_445(self):
        assert si.classify("unknown-service", 445) == "File Sharing"

    def test_unknown_service_name_falls_back_on_port_3306(self):
        assert si.classify("unknown-service", 3306) == "Database"

    def test_unknown_service_name_falls_back_on_port_22(self):
        assert si.classify("unknown-service", 22) == "Remote Access"


# ---------------------------------------------------------------------------
# analyze — full intel record
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_returns_all_required_keys(self):
        result = si.analyze("ssh", 22, "Medium")
        required = {
            "service", "category", "subcategory", "protocol_cleartext",
            "anonymous_risk", "attack_phases", "cve_prone", "notable_cves",
            "enum_commands", "hardening_checks",
        }
        assert required.issubset(result.keys())

    def test_rdp_has_cves(self):
        result = si.analyze("rdp", 3389, "Critical")
        assert result["cve_prone"] is True
        assert len(result["notable_cves"]) > 0
        assert any("BlueKeep" in cve for cve in result["notable_cves"])

    def test_smb_has_eternalblue_cve(self):
        result = si.analyze("smb", 445, "High")
        assert any("EternalBlue" in cve for cve in result["notable_cves"])

    def test_ssh_cleartext_is_false(self):
        assert si.analyze("ssh", 22)["protocol_cleartext"] is False

    def test_telnet_cleartext_is_true(self):
        assert si.analyze("telnet", 23)["protocol_cleartext"] is True

    def test_ftp_anonymous_risk_is_true(self):
        assert si.analyze("ftp", 21)["anonymous_risk"] is True

    def test_ssh_anonymous_risk_is_false(self):
        assert si.analyze("ssh", 22)["anonymous_risk"] is False

    def test_smb_attack_phases_include_lateral_movement(self):
        result = si.analyze("smb", 445)
        assert "Lateral Movement" in result["attack_phases"]

    def test_rdp_attack_phases_include_initial_access(self):
        result = si.analyze("rdp", 3389)
        assert "Initial Access" in result["attack_phases"]

    def test_hardening_checks_nonempty_for_known_service(self):
        result = si.analyze("rdp", 3389, "Low")
        assert len(result["hardening_checks"]) > 0

    def test_unknown_service_returns_fallback_category(self):
        result = si.analyze("completely_unknown_xyz", 65000)
        assert result["category"] == "Unknown"

    def test_unknown_service_still_has_enum_commands(self):
        result = si.analyze("completely_unknown_xyz", 65000, "Low")
        assert len(result["enum_commands"]) > 0


# ---------------------------------------------------------------------------
# analyze — risk gating (cumulative tier unlocking)
# ---------------------------------------------------------------------------

class TestRiskGating:
    def test_low_tier_excludes_hydra(self):
        result = si.analyze("ssh", 22, "Low")
        tools = [cmd["tool"] for cmd in result["enum_commands"]]
        assert "hydra" not in tools

    def test_high_tier_includes_hydra(self):
        result = si.analyze("ssh", 22, "High")
        tools = [cmd["tool"] for cmd in result["enum_commands"]]
        assert "hydra" in tools

    def test_critical_tier_includes_metasploit(self):
        result = si.analyze("ssh", 22, "Critical")
        tools = [cmd["tool"] for cmd in result["enum_commands"]]
        assert "msf" in tools

    def test_critical_includes_all_lower_tiers(self):
        low_cmds      = si.analyze("smb", 445, "Low")["enum_commands"]
        critical_cmds = si.analyze("smb", 445, "Critical")["enum_commands"]
        assert len(critical_cmds) > len(low_cmds)

    def test_low_commands_are_subset_of_critical(self):
        low_commands      = {c["command"] for c in si.analyze("rdp", 3389, "Low")["enum_commands"]}
        critical_commands = {c["command"] for c in si.analyze("rdp", 3389, "Critical")["enum_commands"]}
        assert low_commands.issubset(critical_commands)

    def test_unknown_risk_label_falls_back_to_low(self):
        unknown_result = si.analyze("ssh", 22, "UnknownLabel")
        low_result     = si.analyze("ssh", 22, "Low")
        assert len(unknown_result["enum_commands"]) == len(low_result["enum_commands"])

    def test_enum_commands_have_required_fields(self):
        result = si.analyze("http", 80, "High")
        for cmd in result["enum_commands"]:
            assert "tool"    in cmd
            assert "command" in cmd
            assert "purpose" in cmd


# ---------------------------------------------------------------------------
# enum_strings — backward-compatible flat string list
# ---------------------------------------------------------------------------

class TestEnumStrings:
    def test_returns_list_of_strings(self):
        cmds = si.enum_strings("ssh", 22, "Medium")
        assert isinstance(cmds, list)
        assert all(isinstance(c, str) for c in cmds)

    def test_nonempty_for_known_service(self):
        assert len(si.enum_strings("http", 80, "Medium")) > 0

    def test_more_commands_at_higher_tier(self):
        low_count  = len(si.enum_strings("smb", 445, "Low"))
        high_count = len(si.enum_strings("smb", 445, "High"))
        assert high_count >= low_count
