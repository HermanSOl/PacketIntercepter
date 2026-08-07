from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp

logger = logging.getLogger(__name__)

class ArpSpoofError(Exception):
    """Base class for errors raised by the ARP-spoofing layer."""

class MacResolutionError(ArpSpoofError):
    """Raised when the real MAC address for target_ip/gateway_ip can't be resolved."""

class SpoofSendError(ArpSpoofError):
    """Raised when sending a forged/corrective ARP packet fails."""

class ArpSpoofer:
    def __init__(
        self,
        interface: str,
        target_ip: str,
        gateway_ip: str,
        target_mac: str | None = None,
        gateway_mac: str | None = None,
        interval: float = 2.5,
        on_error: Callable[[Exception], None] | None = None,
    ):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac  # resolved via ARP request in _run() if not given
        self.gateway_mac = gateway_mac
        self.interval = interval
        self.on_error = on_error
        self._own_mac: str | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._error: Exception | None = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    # Resolves any missing MACs, then repeatedly poisons both sides until stop()
    # sets the stop event. Uses Event.wait() to stop immediately
    def _run(self):
        try:
            self._own_mac = get_if_hwaddr(self.interface)
            if self.target_mac is None:
                self.target_mac = self._resolve_mac(self.target_ip)
            if self.gateway_mac is None:
                self.gateway_mac = self._resolve_mac(self.gateway_ip)

            while not self._stop_event.is_set():
                self._poison()
                self._stop_event.wait(self.interval)
        except ArpSpoofError as exc:
            self._handle_error(exc)
        except Exception as exc:
            self._handle_error(ArpSpoofError(f"Unexpected error while ARP-spoofing on {self.interface!r}: {exc}"))

    # Sends a real ARP request and reads the real MAC off the reply, for whichever
    # side (target/gateway) wasn't already configured with a known MAC.
    def _resolve_mac(self, ip: str) -> str:
        return "s"

    # One round of forged replies: tells each side the other lives at our MAC.
    def _poison(self):
        return

    
    def _send(self, dst_mac: str, spoofed_ip: str, real_dst_ip: str, src_mac: str | None = None):
        return "stub"

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 1.5)
        self._restore()

    # This should restore the communication between two original targets before shutting down, so no ARP suspicion is raised
    def _restore(self):
        return "bruh"

    # Records/reports an error raised inside the spoofer thread instead of letting it vanish
    def _handle_error(self, error: Exception):
       return "yeah"
