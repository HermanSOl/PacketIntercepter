"""Entry point for Phase 1: wires ARP spoofing (arp_spoof.py), IP forwarding
(ip_forward.py), the capture layer (pkt_capture_parse.py) and the detection
engine (detection_engine.py) together, so running this script poisons
target_ip<->gateway_ip, keeps their traffic actually flowing through this box,
and sniffs+flags it as it passes through.

Needs enough privilege for scapy to send/sniff raw packets and to flip the
ip_forward sysctl (e.g. via sudo).
"""
from __future__ import annotations

import argparse
import logging
import time

from arp_spoof import ArpSpoofer
from detection_engine import AlertHandler, DnsRule, FtpRule, HttpRule, MailRule, TelnetRule, WeakTlsRule
from ip_forward import IpForwarder, IpForwardError
from pkt_capture_parse import Sniffer

logger = logging.getLogger(__name__)

RULES = [HttpRule(), FtpRule(), TelnetRule(), MailRule(), DnsRule(), WeakTlsRule()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ARP-spoof target_ip <-> gateway_ip and sniff the resulting traffic for insecure protocols."
    )
    parser.add_argument("interface", help="Network interface to spoof/sniff on, e.g. eth0")
    parser.add_argument("target_ip", help="IP of the device being MITM'd, e.g. your laptop")
    parser.add_argument("gateway_ip", help="IP of the router/gateway")
    parser.add_argument("--target-mac", default=None, help="Skip ARP resolution if already known")
    parser.add_argument("--gateway-mac", default=None, help="Skip ARP resolution if already known")
    parser.add_argument("--interval", type=float, default=2.5, help="Seconds between forged ARP replies")
    parser.add_argument(
        "--no-spoof", action="store_true", help="Only sniff/detect - don't send forged ARP replies"
    )
    return parser.parse_args()


def on_spoof_error(error: Exception) -> None:
    print(f"[!] ARP spoofer error: {error}")


def on_sniff_error(error: Exception) -> None:
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
    sniffer = Sniffer(interface=args.interface, rules=RULES, on_sus=handler.process_alert, on_error=on_sniff_error)

    spoofer = None
    forwarder = None
    if not args.no_spoof:
        spoofer = ArpSpoofer(
            interface=args.interface,
            target_ip=args.target_ip,
            gateway_ip=args.gateway_ip,
            target_mac=args.target_mac,
            gateway_mac=args.gateway_mac,
            interval=args.interval,
            on_error=on_spoof_error,
        )
        # Only needed once we're actually redirecting traffic through this box -
        # a pure --no-spoof sniff doesn't put us in the path, so nothing to enable.
        forwarder = IpForwarder()
        try:
            forwarder.enable()
        except IpForwardError as exc:
            print(f"[!] Could not enable IP forwarding, aborting before spoofing starts: {exc}")
            return

    print(f"Sniffing on {args.interface}... press Ctrl+C to stop.")
    sniffer.start()
    if spoofer:
        print(f"Spoofing {args.target_ip} <-> {args.gateway_ip} on {args.interface}... press Ctrl+C to stop.")
        spoofer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        if spoofer:
            spoofer.stop()
        if forwarder:
            forwarder.restore()
        sniffer.stop()
        print_summary(handler)


if __name__ == "__main__":
    main()
