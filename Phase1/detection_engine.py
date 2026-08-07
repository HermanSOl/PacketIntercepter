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


# --- Rules ------------------------------------------------------------------

# Plaintext HTTP traffic (port 80, no TLS)
class HttpRule(DetectionRule):
    PORT = 80

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.PORT in (pkt.sport, pkt.dport):
            return HttpAlert(pkt, "Plaintext HTTP on port 80 - content and any credentials are readable on the wire")
        return None


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


# Telnet session (entire session, including login, is cleartext)
class TelnetRule(DetectionRule):
    PORT = 23

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "TCP" and self.PORT in (pkt.sport, pkt.dport):
            return TelnetAlert(pkt, "Telnet session - entire session including login is cleartext")
        return None


# Unencrypted DNS query (plain port 53)
class DnsRule(DetectionRule):
    PORT = 53

    def check(self, pkt: Packet) -> SusAlert | None:
        if pkt.protocol == "UDP" and self.PORT in (pkt.sport, pkt.dport):
            return DnsAlert(pkt, "Unencrypted DNS query - reveals browsing activity and is trivially spoofable")
        return None

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
