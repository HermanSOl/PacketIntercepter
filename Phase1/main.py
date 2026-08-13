from __future__ import annotations

import argparse
import logging
import time

from arp_spoof import ArpSpoofer
from detection_engine import (
    AlertHandler,
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
from ip_forward import ForwardPolicy, ForwardPolicyError, IpForwarder, IpForwardError
from pkt_capture_parse import Sniffer

logger = logging.getLogger(__name__)

RULES = [
    HttpRule(), FtpRule(), TelnetRule(), MailRule(), DnsRule(), WeakTlsRule(),
    LdapRule(), SnmpRule(), RsyncRule(),
]


# Scopes capture to target_ip's traffic on only the ports RULES can ever match
# on, so bulk traffic on uninteresting ports/protocols (e.g. QUIC on udp/443)
# never reaches the sniffer thread's Python callback. Falls back to no port
# narrowing if any rule reports unrestricted ports (see DetectionRule.bpf_ports).
def build_bpf_filter(target_ip: str, rules: list[DetectionRule]) -> str:
    protos_and_ports: set[tuple[str, int]] = set()
    for rule in rules:
        ports = rule.bpf_ports()
        if ports is None:
            return f"ip and host {target_ip}"
        protos_and_ports.update(ports)

    if not protos_and_ports:
        return f"ip and host {target_ip}"

    port_terms = " or ".join(f"{proto} port {port}" for proto, port in sorted(protos_and_ports))
    return f"ip and host {target_ip} and ({port_terms})"


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
    sniffer = Sniffer(
        interface=args.interface,
        rules=RULES,
        on_sus=handler.process_alert,
        on_error=on_sniff_error,
        bpf_filter=build_bpf_filter(args.target_ip, RULES),
    )

    spoofer = None
    forwarder = None
    forward_policy = None
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
        forwarder = IpForwarder()
        forward_policy = ForwardPolicy()
        try:
            forwarder.enable()
            forward_policy.enable()
        except (IpForwardError, ForwardPolicyError) as exc:
            forwarder.restore()  # in case forwarder.enable() succeeded and only forward_policy.enable() failed
            print(f"[!] Could not enable packet forwarding, aborting before spoofing starts: {exc}")
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
        if forward_policy:
            forward_policy.restore()
        if forwarder:
            forwarder.restore()
        sniffer.stop()
        print_summary(handler)


if __name__ == "__main__":
    main()
