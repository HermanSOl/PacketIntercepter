from __future__ import annotations

import tomllib
from pathlib import Path

from detection_engine import (
    DetectionRule,
    DnsRule,
    FtpRule,
    HttpRule,
    LdapRule,
    MailRule,
    RsyncRule,
    SnmpRule,
    TelnetRule,
    WeakTlsRule,
)

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.toml"
RULE_REGISTRY: dict[str, type[DetectionRule]] = {
    "http": HttpRule,
    "ftp": FtpRule,
    "telnet": TelnetRule,
    "mail": MailRule,
    "dns": DnsRule,
    "weak_tls": WeakTlsRule,
    "ldap": LdapRule,
    "snmp": SnmpRule,
    "rsync": RsyncRule,
}


def load_config(path: Path, required: bool = True) -> dict:
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"Config file not found: {path}")
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def build_rules(config: dict) -> list[DetectionRule]:
    rules_cfg = config.get("rules", {})
    rules: list[DetectionRule] = []
    for name, rule_cls in RULE_REGISTRY.items():
        section = dict(rules_cfg.get(name, {}))
        if not section.pop("enabled", True):
            continue
        rules.append(rule_cls(**_coerce_rule_kwargs(name, section)))
    return rules


def _coerce_rule_kwargs(name: str, section: dict) -> dict:
    kwargs = dict(section)
    if "credential_markers" in kwargs:
        kwargs["credential_markers"] = tuple(m.encode() for m in kwargs["credential_markers"])
    if "default_communities" in kwargs:
        kwargs["default_communities"] = tuple(c.encode() for c in kwargs["default_communities"])
    if name == "mail" and "ports" in kwargs:
        kwargs["ports"] = {int(port): label for port, label in kwargs["ports"].items()}
    if "weak_versions" in kwargs:
        kwargs["weak_versions"] = {bytes.fromhex(hex_key): label for hex_key, label in kwargs["weak_versions"].items()}
    return kwargs
