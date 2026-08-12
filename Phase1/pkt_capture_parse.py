from __future__ import annotations
import logging
import threading
from dataclasses import dataclass
from typing import Callable, TYPE_CHECKING
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw

if TYPE_CHECKING:
    # Only needed for type hints, not at runtime - avoids a circular import
    # with detection_engine.py, which imports Packet from this module too.
    from detection_engine import DetectionRule, SusAlert

logger = logging.getLogger(__name__)


class SnifferError(Exception):
    """Base class for errors raised by the packet-capture layer."""


class InterfaceError(SnifferError):
    """Raised when scapy can't sniff on the configured interface
    (unknown/down interface, insufficient privileges, etc.)."""


class PacketParseError(SnifferError):
    """Raised when a captured packet can't be turned into a Packet summary."""


class Sniffer:
    def __init__(
        self,
        interface: str,
        rules: list[DetectionRule],
        on_sus: Callable[[SusAlert], None],
        on_error: Callable[[Exception], None] | None = None,
        bpf_filter: str | None = None,
    ):
       self.interface = interface
       self.rules = rules
       self.on_sus = on_sus # function called on capture
       self.on_error = on_error
       self.bpf_filter = bpf_filter
       self._thread: threading.Thread | None = None # needs a seperate thread apart from spoofing,etc.
       self._error: Exception | None = None
       self.end = False


    def start(self):
        self._thread = threading.Thread(target=self.start_sniffer, daemon = True)
        self._thread.start()

    # Initializes the sniffer, that will call digest on every packet, stops when self.end = True
    # For now, we won't store packages
    def start_sniffer(self):
        try:
            sniff(
                iface = self.interface,
                prn = self.digest,
                store = False,
                filter = self.bpf_filter,
                stop_filter = lambda _: self.end,
            )
        except (PermissionError, OSError) as exc:
            # unknown/down interface, or not running with correct privileges
            self._handle_error(InterfaceError(f"Unable to sniff on interface {self.interface!r}: {exc}"))
        except Exception as exc: 
            self._handle_error(SnifferError(f"Unexpected error while sniffing on {self.interface!r}: {exc}"))

    # Records/reports an error raised inside the sniffer thread instead of letting it vanish
    def _handle_error(self, error: Exception):
        self._error = error
        logger.exception("Sniffer on %r stopped due to an error", self.interface, exc_info=error)
        if self.on_error:
            try:
                self.on_error(error)
            except Exception:
                logger.exception("on_error handler raised while reporting a sniffer error")

    # Gets a structured summary of the packet, runs it through detection function, parses the summary and any sus alerts forward
    def digest(self, raw_packet) -> "Packet | None":
        try:
            packet_summary = Packet.sum_from_scapy(raw_packet)
        except PacketParseError:
            logger.exception("Failed to parse a captured packet; skipping it")
            return None

        if packet_summary is None:
            return None

        for rule in self.rules:
            try:
                alert = rule.check(packet_summary)
            except Exception:
                logger.exception("Detection rule %r raised while checking a packet; skipping it", rule)
                continue
            if alert:
                try:
                    self.on_sus(alert)
                except Exception:
                    logger.exception("on_sus handler raised while reporting an alert")
        # Returning packet_summary here would make scapy's sniff(prn=...) auto-print
        # its repr() (raw payload bytes and all) for every packet - not what we want.
        return None

    def stop(self):
        self.end = True
        if self._thread:
            self._thread.join(timeout=1.5)



@dataclass
class Packet:
    mac_src: str
    mac_dst: str
    ip_src: str
    ip_dst: str
    protocol: str
    sport: int | None
    dport: int | None
    payload: bytes

    # Builds a Packet based on the packet captured by the sniffer. This packet then is checked for alerts
    @classmethod
    def sum_from_scapy(cls, raw_packet) -> "Packet | None":
        if not raw_packet.haslayer(IP):
            return None  

        try:
            ip_layer = raw_packet[IP]

            if raw_packet.haslayer(TCP):
                protocol = "TCP"
                sport = raw_packet[TCP].sport
                dport = raw_packet[TCP].dport
            elif raw_packet.haslayer(UDP):
                protocol = "UDP"
                sport = raw_packet[UDP].sport
                dport = raw_packet[UDP].dport
            else:
                protocol = str(ip_layer.proto)
                sport = None
                dport = None

            mac_src = raw_packet[Ether].src if raw_packet.haslayer(Ether) else ""
            mac_dst = raw_packet[Ether].dst if raw_packet.haslayer(Ether) else ""
            payload = raw_packet[Raw].load if raw_packet.haslayer(Raw) else b""

            return cls(
                mac_src=mac_src,
                mac_dst=mac_dst,
                ip_src=ip_layer.src,
                ip_dst=ip_layer.dst,
                protocol=protocol,
                sport=sport,
                dport=dport,
                payload=payload,
            )
        except Exception as exc:
            # Malformed/truncated packets are expected on the wire (since this packet might be  the attackers)
            raise PacketParseError(f"Failed to parse captured packet: {exc}") from exc

