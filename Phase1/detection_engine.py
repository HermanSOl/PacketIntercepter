from __future__ import annotations
from abc import ABC, abstractmethod
from collections import deque
from typing import TYPE_CHECKING
import threading
import time

if TYPE_CHECKING:
    from pkt_capture_parse import Packet


class DetectionRule(ABC):
    @abstractmethod
    def check(self, pkt: Packet) -> SusAlert | None:
        ...

    # (protocol, port) pairs for main.build_bpf_filter(). None (the default)
    # means "unrestricted" - a rule that doesn't override this stays fully
    # captured instead of getting silently filtered out.
    def bpf_ports(self) -> tuple[tuple[str, int], ...] | None:
        return None


class SusAlert:
    def __init__(self, pkt: Packet, reason: str):
        self.pkt = pkt
        self.reason = reason  # short, human-readable explanation for later display
        self.timestamp = time.time()  # when the alert was raised, for later display/ordering
        self.id: int | None = None  # assigned by AlertHandler.process_alert() - None until then

    def __repr__(self):
        return f"{self.__class__.__name__}({self.reason!r})"


class HttpAlert(SusAlert):
    pass


class FtpAlert(SusAlert):
    pass


class TelnetAlert(SusAlert):
    pass


class DnsAlert(SusAlert):
    pass

class MailAlert(SusAlert):
    pass


class WeakTlsAlert(SusAlert):
    pass


class LdapAlert(SusAlert):
    pass


class SnmpAlert(SusAlert):
    pass


class RsyncAlert(SusAlert):
    pass


# --- Rules ------------------------------------------------------------------

# Plaintext HTTP traffic (port 80, no TLS)
class HttpRule(DetectionRule):
    DEFAULT_PORT = 80

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.port in (pkt.sport, pkt.dport):
            return HttpAlert(pkt, f"Plaintext HTTP on port {self.port} - content and any credentials are readable on the wire")
        return None

    def bpf_ports(self):
        return (("tcp", self.port),)


# FTP login sequence (USER/PASS sent in cleartext on the control channel)
class FtpRule(DetectionRule):
    DEFAULT_CONTROL_PORT = 21
    DEFAULT_CREDENTIAL_MARKERS = (b"USER ", b"PASS ")

    def __init__(self, control_port: int = DEFAULT_CONTROL_PORT, credential_markers: tuple[bytes, ...] = DEFAULT_CREDENTIAL_MARKERS):
        self.control_port = control_port
        self.credential_markers = credential_markers

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP" or self.control_port not in (pkt.sport, pkt.dport):
            return None
        if any(pkt.payload.startswith(marker) for marker in self.credential_markers):
            return FtpAlert(pkt, "FTP USER/PASS sent in cleartext - credentials exposed")
        return None

    def bpf_ports(self):
        return (("tcp", self.control_port),)


# Telnet session (entire session, including login, is cleartext)
class TelnetRule(DetectionRule):
    DEFAULT_PORT = 23

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.port in (pkt.sport, pkt.dport):
            return TelnetAlert(pkt, "Telnet session - entire session including login is cleartext")
        return None

    def bpf_ports(self):
        return (("tcp", self.port),)


# Unencrypted DNS query (plain port 53)
class DnsRule(DetectionRule):
    DEFAULT_PORT = 53

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "UDP" and self.port in (pkt.sport, pkt.dport):
            return DnsAlert(pkt, "Unencrypted DNS query - reveals browsing activity and is trivially spoofable")
        return None

    def bpf_ports(self):
        return (("udp", self.port),)


class MailRule(DetectionRule):
    DEFAULT_PORTS = {25: "SMTP", 110: "POP3", 143: "IMAP"}

    def __init__(self, ports: dict[int, str] | None = None):
        self.ports = dict(ports) if ports is not None else dict(self.DEFAULT_PORTS)

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP":
            return None
        for port in (pkt.sport, pkt.dport):
            name = self.ports.get(port)
            if name:
                return MailAlert(pkt, f"Unencrypted {name} traffic - mail content/credentials exposed")
        return None

    def bpf_ports(self):
        return tuple(("tcp", port) for port in self.ports)


## This rule checks byte for byte to ensure that all of them are in place.
# For now this is still weak, as it only reads fixed bytes positions and doesn't account for extensions
class WeakTlsRule(DetectionRule):
    HANDSHAKE_CONTENT_TYPE = 0x16
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    HELLO_TYPES = {CLIENT_HELLO: "ClientHello", SERVER_HELLO: "ServerHello"}
    MIN_LEN = 11  # record header (5) + handshake header (4) + version (2)
    DEFAULT_WEAK_VERSIONS = {
        b"\x03\x01": "TLS 1.0",
        b"\x03\x02": "TLS 1.1",
    }
    DEFAULT_BPF_PORTS = (443, 465, 587, 993, 995, 8443)

    def __init__(self, weak_versions: dict[bytes, str] | None = None, bpf_ports: tuple[int, ...] = DEFAULT_BPF_PORTS):
        self.weak_versions = dict(weak_versions) if weak_versions is not None else dict(self.DEFAULT_WEAK_VERSIONS)
        self._bpf_port_numbers = tuple(bpf_ports)

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP" or len(pkt.payload) < self.MIN_LEN:
            return None

        payload = pkt.payload
        if payload[0] != self.HANDSHAKE_CONTENT_TYPE:
            return None

        hello_name = self.HELLO_TYPES.get(payload[5])
        if hello_name is None:
            return None

        version_name = self.weak_versions.get(payload[9:11])
        if version_name is None:
            return None

        return WeakTlsAlert(pkt, f"{hello_name} proposes {version_name} - deprecated, vulnerable TLS version")

    def bpf_ports(self):
        return tuple(("tcp", port) for port in self._bpf_port_numbers)


# LDAP simple bind.
class LdapRule(DetectionRule):
    DEFAULT_PORT = 389
    BIND_REQUEST_TAG = 0x60  
    SIMPLE_AUTH_TAG = 0x80   

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP" or self.port not in (pkt.sport, pkt.dport):
            return None
        bind_at = pkt.payload.find(bytes([self.BIND_REQUEST_TAG]))
        if bind_at == -1:
            return None
        if bytes([self.SIMPLE_AUTH_TAG]) in pkt.payload[bind_at:]:
            return LdapAlert(pkt, "LDAP simple bind - directory credentials sent in cleartext")
        return None

    def bpf_ports(self):
        return (("tcp", self.port),)


# SNMP using a default string
class SnmpRule(DetectionRule):
    DEFAULT_PORT = 161
    DEFAULT_COMMUNITIES = (b"public", b"private")

    def __init__(self, port: int = DEFAULT_PORT, default_communities: tuple[bytes, ...] = DEFAULT_COMMUNITIES):
        self.port = port
        self.default_communities = default_communities

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "UDP" or self.port not in (pkt.sport, pkt.dport):
            return None
        for community in self.default_communities:
            if community in pkt.payload:
                return SnmpAlert(
                    pkt,
                    f"SNMP using default community string {community.decode()!r} - "
                    "full read/write access to the device if it's writable",
                )
        return None

    def bpf_ports(self):
        return (("udp", self.port),)


# Rsync daemon traffic (port 873) - flagged by port alone, same as TelnetRule
class RsyncRule(DetectionRule):
    DEFAULT_PORT = 873

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.port in (pkt.sport, pkt.dport):
            return RsyncAlert(
                pkt,
                "Rsync daemon traffic (port 873) - module may allow anonymous access "
                "to the full filesystem tree; verify auth is configured",
            )
        return None

    def bpf_ports(self):
        return (("tcp", self.port),)


class AlertHandler:
    def __init__(self, maxlen: int = 500):
        self.lock = threading.Lock()
        self.alerts: deque[SusAlert] = deque(maxlen=maxlen)
        self._next_id = 0

    def process_alert(self, alert: SusAlert):
        with self.lock:
            alert.id = self._next_id
            self._next_id += 1
            self.alerts.append(alert)

    def get_alerts(self) -> list[SusAlert]:
        with self.lock:
            return list(self.alerts)
