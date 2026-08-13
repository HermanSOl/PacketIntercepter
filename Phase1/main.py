from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from arp_spoof import ArpSpoofer
from config import DEFAULT_CONFIG_PATH, build_rules, load_config
from detection_engine import AlertHandler, DetectionRule
from ip_forward import ForwardPolicy, ForwardPolicyError, IpForwarder, IpForwardError
from pkt_capture_parse import FlowTracker, Sniffer

logger = logging.getLogger(__name__)

# The default rule set (every rule enabled, hardcoded defaults) - used when no
# config.toml is present, and as the baseline TestBuildBpfFilter checks
# against. main() builds the actual (possibly config-narrowed) rule list from
# the loaded config instead of using this directly.
RULES = build_rules({})


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
    parser.add_argument(
        "--interval", type=float, default=None,
        help="Seconds between forged ARP replies (default: config.toml's arp_spoof.interval, or 2.5)",
    )
    parser.add_argument(
        "--no-spoof", action="store_true", help="Only sniff/detect - don't send forged ARP replies"
    )
    parser.add_argument(
        "--config", default=None,
        help=f"Path to a TOML tunables file (default: {DEFAULT_CONFIG_PATH} if present)",
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

    # --config points at an explicit file (errors if missing); with no flag,
    # config.toml next to main.py is used if present, else every tunable
    # below just keeps its hardcoded default (config == {}).
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    config = load_config(config_path, required=bool(args.config))

    rules = build_rules(config)
    interval = args.interval if args.interval is not None else config.get("arp_spoof", {}).get("interval", 2.5)
    bpf_filter = config.get("capture", {}).get("bpf_filter") or build_bpf_filter(args.target_ip, rules)

    handler = AlertHandler(**config.get("alerts", {}))
    sniffer = Sniffer(
        interface=args.interface,
        rules=rules,
        on_sus=handler.process_alert,
        on_error=on_sniff_error,
        bpf_filter=bpf_filter,
        flow_tracker=FlowTracker(**config.get("flow_tracker", {})),
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
            interval=interval,
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
