from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"
IPTABLES_BIN = "iptables"


class IpForwardError(Exception):
    """Raised when the IPv4 forwarding sysctl can't be read or written."""


class ForwardPolicyError(Exception):
    """Raised when the netfilter FORWARD chain's default policy can't be read or set."""


class IpForwarder:
    def __init__(self, path: str = IP_FORWARD_PATH):
        self.path = path
        self._original_value: str | None = None  # set by enable(), consumed by restore()

    def _read(self) -> str:
        try:
            with open(self.path) as f:
                return f.read().strip()
        except OSError as exc:
            raise IpForwardError(f"Failed to read {self.path!r}: {exc}") from exc

    def _write(self, value: str) -> None:
        try:
            with open(self.path, "w") as f:
                f.write(value)
        except OSError as exc:
            raise IpForwardError(f"Failed to write {value!r} to {self.path!r}: {exc}") from exc

    # Records whatever forwarding was set to before we touch it
    def enable(self) -> None:
        self._original_value = self._read()
        if self._original_value == "1":
            logger.info("IP forwarding was already enabled")
            return
        self._write("1")
        logger.info("IP forwarding enabled (was %r)", self._original_value)

    # Puts forwarding back to whatever it was before enable()
    def restore(self) -> None:
        if self._original_value is None or self._original_value == "1":
            return
        self._write(self._original_value)
        logger.info("IP forwarding restored to %r", self._original_value)
        self._original_value = None


class ForwardPolicy:
    """Ensures the netfilter FORWARD chain's default policy is ACCEPT while
    spoofing is active, and puts it back on stop() - same record/restore shape
    as IpForwarder, but for the firewall policy rather than the sysctl.
    """

    def __init__(self, chain: str = "FORWARD", iptables_bin: str = IPTABLES_BIN):
        self.chain = chain
        self.iptables_bin = iptables_bin
        self._original_policy: str | None = None  # set by enable(), consumed by restore()

    def _read_policy(self) -> str:
        try:
            result = subprocess.run(
                [self.iptables_bin, "-S", self.chain],
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ForwardPolicyError(f"Failed to read {self.chain} chain policy: {exc}") from exc

        prefix = f"-P {self.chain} "
        for line in result.stdout.splitlines():
            if line.startswith(prefix):
                return line[len(prefix):].split()[0]
        raise ForwardPolicyError(f"Could not find a policy for chain {self.chain!r} in iptables output")

    def _write_policy(self, policy: str) -> None:
        try:
            subprocess.run(
                [self.iptables_bin, "-P", self.chain, policy],
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ForwardPolicyError(f"Failed to set {self.chain} chain policy to {policy!r}: {exc}") from exc

    # Records whatever the policy was
    def enable(self) -> None:
        self._original_policy = self._read_policy()
        if self._original_policy == "ACCEPT":
            logger.info("%s chain policy was already ACCEPT", self.chain)
            return
        self._write_policy("ACCEPT")
        logger.info("%s chain policy set to ACCEPT (was %r)", self.chain, self._original_policy)

    # Puts the policy back to whatever it was before enable()
    def restore(self) -> None:
        if self._original_policy is None or self._original_policy == "ACCEPT":
            return
        self._write_policy(self._original_policy)
        logger.info("%s chain policy restored to %r", self.chain, self._original_policy)
        self._original_policy = None
