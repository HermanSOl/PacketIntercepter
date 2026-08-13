"""Tests for config.py's TOML tunables loader."""
from __future__ import annotations

from pathlib import Path

import pytest

from config import RULE_REGISTRY, build_rules, load_config
from detection_engine import DnsRule, FtpRule, HttpRule, MailRule, WeakTlsRule


class TestLoadConfig:
    def test_missing_default_path_returns_empty_dict_when_not_required(self, tmp_path):
        assert load_config(tmp_path / "no-such-config.toml", required=False) == {}

    def test_missing_explicit_path_raises_when_required(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "no-such-config.toml", required=True)

    def test_parses_an_existing_toml_file(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text('[alerts]\nmaxlen = 42\n')

        config = load_config(path, required=False)

        assert config == {"alerts": {"maxlen": 42}}

    def test_shipped_config_toml_loads_and_reproduces_the_hardcoded_defaults(self):
        # Phase1/config.toml is meant to be an editable, human-readable mirror
        # of every rule's hardcoded defaults - if it drifts, build_rules(cfg)
        # should still produce the exact same rules as build_rules({}).
        shipped_path = Path(__file__).parent.parent / "config.toml"
        config = load_config(shipped_path, required=True)

        default_rules = build_rules({})
        shipped_rules = build_rules(config)

        assert [type(r) for r in shipped_rules] == [type(r) for r in default_rules]
        assert [r.bpf_ports() for r in shipped_rules] == [r.bpf_ports() for r in default_rules]


class TestBuildRules:
    def test_empty_config_builds_every_rule_in_registry_order(self):
        rules = build_rules({})

        assert [type(r) for r in rules] == list(RULE_REGISTRY.values())

    def test_enabled_false_omits_the_rule(self):
        rules = build_rules({"rules": {"http": {"enabled": False}}})

        assert not any(isinstance(r, HttpRule) for r in rules)
        assert len(rules) == len(RULE_REGISTRY) - 1

    def test_extra_keys_are_passed_through_as_constructor_kwargs(self):
        rules = build_rules({"rules": {"dns": {"port": 5353}}})

        dns_rule = next(r for r in rules if isinstance(r, DnsRule))
        assert dns_rule.port == 5353
        assert dns_rule.bpf_ports() == (("udp", 5353),)

    def test_credential_markers_are_encoded_to_bytes(self):
        rules = build_rules({"rules": {"ftp": {"credential_markers": ["LOGIN "]}}})

        ftp_rule = next(r for r in rules if isinstance(r, FtpRule))
        assert ftp_rule.credential_markers == (b"LOGIN ",)

    def test_mail_ports_string_keys_are_coerced_to_int(self):
        rules = build_rules({"rules": {"mail": {"ports": {"2525": "SMTP-alt"}}}})

        mail_rule = next(r for r in rules if isinstance(r, MailRule))
        assert mail_rule.ports == {2525: "SMTP-alt"}

    def test_weak_versions_hex_keys_are_coerced_to_bytes(self):
        rules = build_rules({"rules": {"weak_tls": {"weak_versions": {"0300": "SSL 3.0"}}}})

        tls_rule = next(r for r in rules if isinstance(r, WeakTlsRule))
        assert tls_rule.weak_versions == {b"\x03\x00": "SSL 3.0"}
