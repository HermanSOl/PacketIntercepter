from __future__ import annotations
from abc import ABC, abstractmethod
from collections import deque
from typing import TYPE_CHECKING
import threading

if TYPE_CHECKING:
    # Only needed for type hints, not at runtime - avoids a circular import
    # with pkt_capture_parse.py, which imports from this module too.
    from pkt_capture_parse import Packet


class DetectionRule(ABC):
    # Returns a SusAlert if pkt trips this rule's condition, else None.
    # Each subclass decides for itself what it needs to look at in pkt.
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


# --- Rules ------------------------------------------------------------------

# Plaintext HTTP traffic (port 80, no TLS)
class HttpRule(DetectionRule):
    PORT = 80

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.PORT in (pkt.sport, pkt.dport):
            return HttpAlert(pkt, "Plaintext HTTP on port 80 - content and any credentials are readable on the wire")
        return None

    def bpf_ports(self):
        return (("tcp", self.PORT),)


# FTP login sequence (USER/PASS sent in cleartext on the control channel)
class FtpRule(DetectionRule):
    CONTROL_PORT = 21
    CREDENTIAL_MARKERS = (b"USER ", b"PASS ")

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP" or self.CONTROL_PORT not in (pkt.sport, pkt.dport):
            return None
        if any(pkt.payload.startswith(marker) for marker in self.CREDENTIAL_MARKERS):
            return FtpAlert(pkt, "FTP USER/PASS sent in cleartext - credentials exposed")
        return None

    def bpf_ports(self):
        return (("tcp", self.CONTROL_PORT),)


# Telnet session (entire session, including login, is cleartext)
class TelnetRule(DetectionRule):
    PORT = 23

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.PORT in (pkt.sport, pkt.dport):
            return TelnetAlert(pkt, "Telnet session - entire session including login is cleartext")
        return None

    def bpf_ports(self):
        return (("tcp", self.PORT),)


# Unencrypted DNS query (plain port 53)
class DnsRule(DetectionRule):
    PORT = 53

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "UDP" and self.PORT in (pkt.sport, pkt.dport):
            return DnsAlert(pkt, "Unencrypted DNS query - reveals browsing activity and is trivially spoofable")
        return None

    def bpf_ports(self):
        return (("udp", self.PORT),)


class MailRule(DetectionRule):
    PORTS = {25: "SMTP", 110: "POP3", 143: "IMAP"}

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP":
            return None
        for port in (pkt.sport, pkt.dport):
            name = self.PORTS.get(port)
            if name:
                return MailAlert(pkt, f"Unencrypted {name} traffic - mail content/credentials exposed")
        return None

    def bpf_ports(self):
        return tuple(("tcp", port) for port in self.PORTS)


## This rule checks byte for byte to ensure that all of them are in place.
# For now this is still weak, as it only reads fixed bytes positions and doesn't account for extensions
class WeakTlsRule(DetectionRule):
    HANDSHAKE_CONTENT_TYPE = 0x16
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    HELLO_TYPES = {CLIENT_HELLO: "ClientHello", SERVER_HELLO: "ServerHello"}
    WEAK_VERSIONS = {
        b"\x03\x01": "TLS 1.0",
        b"\x03\x02": "TLS 1.1",
    }
    MIN_LEN = 11  # record header (5) + handshake header (4) + version (2)

    # For bpf_ports() only - check() stays port-agnostic. Without this list,
    # main.build_bpf_filter() can't narrow the capture at all. Trade-off: TLS
    # on a port not listed here won't be captured.
    BPF_PORTS = (443, 465, 587, 993, 995, 8443)

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol != "TCP" or len(pkt.payload) < self.MIN_LEN:
            return None

        payload = pkt.payload
        if payload[0] != self.HANDSHAKE_CONTENT_TYPE:
            return None

        hello_name = self.HELLO_TYPES.get(payload[5])
        if hello_name is None:
            return None

        version_name = self.WEAK_VERSIONS.get(payload[9:11])
        if version_name is None:
            return None

        return WeakTlsAlert(pkt, f"{hello_name} proposes {version_name} - deprecated, vulnerable TLS version")

    def bpf_ports(self):
        return tuple(("tcp", port) for port in self.BPF_PORTS)


class AlertHandler:
    def __init__(self, maxlen: int = 500):
        self.lock = threading.Lock()
        self.alerts: deque[SusAlert] = deque(maxlen=maxlen)

    def process_alert(self, alert: SusAlert):
        with self.lock:
            self.alerts.append(alert)

    def get_alerts(self) -> list[SusAlert]:
        with self.lock:
            return list(self.alerts)
