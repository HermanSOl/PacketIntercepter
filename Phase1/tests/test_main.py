"""Tests for main.py's build_bpf_filter()."""
from __future__ import annotations

from detection_engine import DetectionRule, DnsRule, HttpRule, WeakTlsRule
from main import RULES, build_bpf_filter


class TestBuildBpfFilter:
    def test_scopes_to_host_and_ors_together_every_rules_ports(self):
        bpf_filter = build_bpf_filter("10.0.0.5", [HttpRule(), DnsRule()])

        assert bpf_filter == "ip and host 10.0.0.5 and (tcp port 80 or udp port 53)"

    def test_deduplicates_ports_shared_by_multiple_rules(self):
        bpf_filter = build_bpf_filter("10.0.0.5", [HttpRule(), HttpRule()])

        assert bpf_filter == "ip and host 10.0.0.5 and (tcp port 80)"

    def test_falls_back_to_unrestricted_when_any_rule_is_unrestricted(self):
        class UnrestrictedRule(DetectionRule):
            def check(self, pkt):
                return None

        bpf_filter = build_bpf_filter("10.0.0.5", [HttpRule(), UnrestrictedRule()])

        assert bpf_filter == "ip and host 10.0.0.5"

    def test_falls_back_to_unrestricted_for_an_empty_rule_list(self):
        assert build_bpf_filter("10.0.0.5", []) == "ip and host 10.0.0.5"

    def test_default_rules_list_produces_a_stable_narrowed_filter(self):
        # Locks in that RULES (as actually wired up in main()) still narrows
        # rather than silently falling back to unrestricted.
        bpf_filter = build_bpf_filter("10.0.0.5", RULES)

        assert bpf_filter.startswith("ip and host 10.0.0.5 and (")
        assert "tcp port 443" in bpf_filter  # WeakTlsRule
        assert "udp port 53" in bpf_filter  # DnsRule
