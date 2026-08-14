from __future__ import annotations
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
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


class FlowTracker:
    """Caps how many packets per flow direction get fully dissected/checked -
    what a flow's port/handshake say is decided within its first few packets.
    """

    def __init__(self, budget: int = 4, max_flows: int = 50_000):
        self.budget = budget
        self.max_flows = max_flows
        self._remaining: dict[tuple, int] = {}

    def should_inspect(self, flow_key: tuple) -> bool:
        remaining = self._remaining.get(flow_key, self.budget)
        if remaining <= 0:
            return False
        if flow_key not in self._remaining and len(self._remaining) >= self.max_flows:
            self._remaining.clear()
        self._remaining[flow_key] = remaining - 1
        return True


@dataclass
class LoggedPacket:
    protocol: str
    ip_src: str
    sport: int | None
    ip_dst: str
    dport: int | None
    pkt: "Packet | None"
    timestamp: float = field(default_factory=time.time)
    id: int | None = None  # assigned by PacketLog.process_packet() - None until then
    alerts: list["SusAlert"] = field(default_factory=list)


class PacketLog:
    def __init__(self, maxlen: int = 2000):
        self.lock = threading.Lock()
        self.packets: deque[LoggedPacket] = deque(maxlen=maxlen)
        self._next_id = 0

    def process_packet(self, logged: LoggedPacket) -> None:
        with self.lock:
            logged.id = self._next_id
            self._next_id += 1
            self.packets.append(logged)

    def get_packets(self) -> list[LoggedPacket]:
        with self.lock:
            return list(self.packets)


class Sniffer:
    def __init__(
        self,
        interface: str,
        rules: list[DetectionRule],
        on_sus: Callable[[SusAlert], None],
        on_error: Callable[[Exception], None] | None = None,
        bpf_filter: str | None = None,
        flow_tracker: FlowTracker | None = None,
        packet_log: PacketLog | None = None,
    ):
       self.interface = interface
       self.rules = rules
       self.on_sus = on_sus # function called on capture
       self.on_error = on_error
       self.bpf_filter = bpf_filter
       self.flow_tracker = flow_tracker if flow_tracker is not None else FlowTracker()
       self.packet_log = packet_log if packet_log is not None else PacketLog()
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
        flow_key = Packet.flow_key_from_scapy(raw_packet)
        if flow_key is None:
            return None  # not IP - the BPF filter should already exclude these
        protocol, ip_src, sport, ip_dst, dport = flow_key

        packet_summary = None
        alerts: list[SusAlert] = []
        if self.flow_tracker.should_inspect(flow_key):
            try:
                packet_summary = Packet.sum_from_scapy(raw_packet)
            except PacketParseError:
                logger.exception("Failed to parse a captured packet; skipping it")
                packet_summary = None

            if packet_summary is not None:
                for rule in self.rules:
                    try:
                        alert = rule.check(packet_summary)
                    except Exception:
                        logger.exception("Detection rule %r raised while checking a packet; skipping it", rule)
                        continue
                    if alert:
                        alerts.append(alert)
                        try:
                            self.on_sus(alert)
                        except Exception:
                            logger.exception("on_sus handler raised while reporting an alert")

        logged = LoggedPacket(protocol, ip_src, sport, ip_dst, dport, packet_summary, alerts=alerts)
        self.packet_log.process_packet(logged)
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
    length: int = 0 
    eth_type: int | None = None 
    ip_ttl: int | None = None
    ip_id: int | None = None
    ip_flags: str = ""
    ip_proto_num: int | None = None 
    ip_checksum: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_flags: str = "" 
    tcp_window: int | None = None

    @staticmethod
    def flow_key_from_scapy(raw_packet) -> tuple | None:
        if not raw_packet.haslayer(IP):
            return None
        ip_layer = raw_packet[IP]
        if raw_packet.haslayer(TCP):
            tcp = raw_packet[TCP]
            return ("TCP", ip_layer.src, tcp.sport, ip_layer.dst, tcp.dport)
        if raw_packet.haslayer(UDP):
            udp = raw_packet[UDP]
            return ("UDP", ip_layer.src, udp.sport, ip_layer.dst, udp.dport)
        return (str(ip_layer.proto), ip_layer.src, None, ip_layer.dst, None)

    # Builds a Packet based on the packet captured by the sniffer. This packet then is checked for alerts
    @classmethod
    def sum_from_scapy(cls, raw_packet) -> "Packet | None":
        if not raw_packet.haslayer(IP):
            return None  

        try:
            ip_layer = raw_packet[IP]
            tcp_seq = tcp_ack = tcp_window = None
            tcp_flags = ""

            if raw_packet.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = raw_packet[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                tcp_seq = tcp_layer.seq
                tcp_ack = tcp_layer.ack
                tcp_flags = str(tcp_layer.flags)
                tcp_window = tcp_layer.window
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
            eth_type = raw_packet[Ether].type if raw_packet.haslayer(Ether) else None
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
                length=len(raw_packet),
                eth_type=eth_type,
                ip_ttl=ip_layer.ttl,
                ip_id=ip_layer.id,
                ip_flags=str(ip_layer.flags),
                ip_proto_num=int(ip_layer.proto),
                ip_checksum=ip_layer.chksum,
                tcp_seq=tcp_seq,
                tcp_ack=tcp_ack,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
            )
        except Exception as exc:
            # Malformed/truncated packets are expected on the wire (since this packet might be  the attackers)
            raise PacketParseError(f"Failed to parse captured packet: {exc}") from exc

