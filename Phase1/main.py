from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from scapy.all import get_if_addr

from arp_spoof import ArpSpoofer
from config import DEFAULT_CONFIG_PATH, build_rules, load_config
from detection_engine import AlertHandler, DetectionRule
from ip_forward import (
    ForwardPolicy,
    ForwardPolicyError,
    IpForwarder,
    IpForwardError,
    RedirectPolicy,
    RedirectPolicyError,
)
from pkt_capture_parse import FlowTracker, PacketLog, Sniffer

logger = logging.getLogger(__name__)

# default build here just in case no config
RULES = build_rules({})


def build_bpf_filter(target_ip: str, rules: list[DetectionRule], exclude_ips: tuple[str, ...] = ()) -> str:
    # exclude_ips keeps local-network chatter (target<->gateway, target<->this box)
    # out of capture - except DNS (udp/53), which stays visible even to an excluded IP.
    # DNS to a local resolver is exactly what DnsRule exists to catch ("reveals browsing
    # activity"); excluding it outright would blind the tool to real signal, not just noise.
    exclude_terms = "".join(f" and (not host {ip} or udp port 53)" for ip in exclude_ips)

    protos_and_ports: set[tuple[str, int]] = set()
    for rule in rules:
        ports = rule.bpf_ports()
        if ports is None:
            return f"ip and host {target_ip}{exclude_terms}"
        protos_and_ports.update(ports)

    if not protos_and_ports:
        return f"ip and host {target_ip}{exclude_terms}"

    port_terms = " or ".join(f"{proto} port {port}" for proto, port in sorted(protos_and_ports))
    return f"ip and host {target_ip}{exclude_terms} and ({port_terms})"


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
    parser.add_argument(
        "--no-ui", action="store_true",
        help="Don't serve the local web UI of flagged packets (it runs at "
             "http://127.0.0.1:<--ui-port> by default - needs Flask)",
    )
    parser.add_argument(
        "--ui-port", type=int, default=5001, help="Port for the web UI (default: 5001, ignored with --no-ui)"
    )
    parser.add_argument(
        "--no-bpf-filter", action="store_true",
        help="Capture unfiltered instead of the rule-derived BPF filter - only affects what "
             "the sniffer sees for detection/UI display, not forwarding. For isolating whether "
             "BPF filtering is implicated in a connectivity problem.",
    )
    parser.add_argument(
        "--no-forward-policy", action="store_true",
        help="Don't force the netfilter FORWARD chain to ACCEPT while spoofing. For isolating "
             "whether that's implicated in a connectivity problem.",
    )
    parser.add_argument(
        "--no-redirect-policy", action="store_true",
        help="Don't disable ICMP redirects while spoofing. For isolating whether that's "
             "implicated in a connectivity problem.",
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
    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    config = load_config(config_path, required=bool(args.config))

    rules = build_rules(config)
    interval = args.interval if args.interval is not None else config.get("arp_spoof", {}).get("interval", 2.5)
    # Keeps target<->gateway and target<->this-box local chatter out of capture -
    # see build_bpf_filter()'s docstring for why that never excludes real internet traffic.
    own_ip = get_if_addr(args.interface)
    exclude_ips = tuple(ip for ip in (args.gateway_ip, own_ip) if ip and ip != "0.0.0.0")
    if args.no_bpf_filter:
        bpf_filter = None
    else:
        bpf_filter = config.get("capture", {}).get("bpf_filter") or build_bpf_filter(
            args.target_ip, rules, exclude_ips=exclude_ips
        )

    handler = AlertHandler(**config.get("alerts", {}))
    packet_log = PacketLog(**config.get("packet_log", {}))
    sniffer = Sniffer(
        interface=args.interface,
        rules=rules,
        on_sus=handler.process_alert,
        on_error=on_sniff_error,
        bpf_filter=bpf_filter,
        flow_tracker=FlowTracker(**config.get("flow_tracker", {})),
        packet_log=packet_log,
    )

    spoofer = None
    forwarder = None
    forward_policy = None
    redirect_policy = None
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
        # forwarder itself (net.ipv4.ip_forward) always runs when spoofing - without it
        # nothing routes at all, for any target OS, so it can't help isolate an
        # OS-specific problem the way --no-forward-policy/--no-redirect-policy can.
        forwarder = IpForwarder()
        forward_policy = None if args.no_forward_policy else ForwardPolicy()
        redirect_policy = None if args.no_redirect_policy else RedirectPolicy(args.interface)
        try:
            forwarder.enable()
            if forward_policy:
                forward_policy.enable()
            if redirect_policy:
                redirect_policy.enable()
        except (IpForwardError, ForwardPolicyError, RedirectPolicyError) as exc:
            # in case an earlier step succeeded and a later one failed - each restore() is a
            # no-op if its own enable() never got that far
            if redirect_policy:
                redirect_policy.restore()
            if forward_policy:
                forward_policy.restore()
            forwarder.restore()
            print(f"[!] Could not enable packet forwarding, aborting before spoofing starts: {exc}")
            return

    if not args.no_ui:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ui.server import run_ui

        run_ui(handler, packet_log, port=args.ui_port)
        print(f"UI available at http://127.0.0.1:{args.ui_port}")

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
        if redirect_policy:
            redirect_policy.restore()
        if forward_policy:
            forward_policy.restore()
        if forwarder:
            forwarder.restore()
        sniffer.stop()
        print_summary(handler)


if __name__ == "__main__":
    main()
