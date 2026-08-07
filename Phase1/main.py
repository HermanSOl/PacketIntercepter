"""Entry point for Phase 1: wires the capture layer (pkt_capture_parse.py) to
the detection engine (detection_engine.py) and runs them on a real interface.

ARP spoofing + IP forwarding (Phase 1 steps 1-2) aren't built yet, so this
only sees whatever traffic already reaches this box - it doesn't redirect
anyone's traffic here itself. Needs to run with enough privilege for scapy
to sniff (e.g. via sudo).
"""
from __future__ import annotations

import argparse
import logging
import time

from detection_engine import AlertHandler, DnsRule, FtpRule, HttpRule, MailRule, TelnetRule, WeakTlsRule
from pkt_capture_parse import Sniffer

logger = logging.getLogger(__name__)

RULES = [HttpRule(), FtpRule(), TelnetRule(), MailRule(), DnsRule(), WeakTlsRule()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sniff an interface and flag insecure-protocol traffic.")
    parser.add_argument("interface", help="Network interface to sniff on, e.g. eth0")
    return parser.parse_args()


def on_error(error: Exception) -> None:
    print(f"[!] Sniffer error: {error}")


def print_summary(handler: AlertHandler) -> None:
    alerts = handler.get_alerts()
    if not alerts:
        print("\nNo insecure traffic detected.")
        return

    print(f"\n{len(alerts)} alert(s) detected:")
    for alert in alerts:
        pkt = alert.pkt
        print(f"  [{alert.__class__.__name__}] {pkt.ip_src}:{pkt.sport} -> {pkt.ip_dst}:{pkt.dport} - {alert.reason}")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    args = parse_args()

    handler = AlertHandler()
    sniffer = Sniffer(interface=args.interface, rules=RULES, on_sus=handler.process_alert, on_error=on_error)

    print(f"Sniffing on {args.interface}... press Ctrl+C to stop.")
    sniffer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        sniffer.stop()
        print_summary(handler)


if __name__ == "__main__":
    main()
