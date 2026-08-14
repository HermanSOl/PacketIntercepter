from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"
IPTABLES_BIN = "iptables"
SEND_REDIRECTS_PATH_TMPL = "/proc/sys/net/ipv4/conf/{scope}/send_redirects"


class IpForwardError(Exception):
    """Raised when the IPv4 forwarding sysctl can't be read or written."""


class ForwardPolicyError(Exception):
    """Raised when the netfilter FORWARD chain's default policy can't be read or set."""


class RedirectPolicyError(Exception):
    """Raised when a send_redirects sysctl can't be read or written."""


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


class RedirectPolicy:
    def __init__(self, interface: str, path_tmpl: str = SEND_REDIRECTS_PATH_TMPL):
        self.interface = interface
        self._paths = {"all": path_tmpl.format(scope="all"), interface: path_tmpl.format(scope=interface)}
        self._original_values: dict[str, str] | None = None  # set by enable(), consumed by restore()

    def _read(self, path: str) -> str:
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError as exc:
            raise RedirectPolicyError(f"Failed to read {path!r}: {exc}") from exc

    def _write(self, path: str, value: str) -> None:
        try:
            with open(path, "w") as f:
                f.write(value)
        except OSError as exc:
            raise RedirectPolicyError(f"Failed to write {value!r} to {path!r}: {exc}") from exc

    # Records whatever send_redirects was set to before we touch it, for each scope
    def enable(self) -> None:
        self._original_values = {scope: self._read(path) for scope, path in self._paths.items()}
        for scope, path in self._paths.items():
            if self._original_values[scope] == "0":
                continue
            self._write(path, "0")
        logger.info("ICMP redirects disabled on all/%s (were %r)", self.interface, self._original_values)

    # Puts send_redirects back to whatever it was before enable(), for each scope
    def restore(self) -> None:
        if self._original_values is None:
            return
        for scope, path in self._paths.items():
            value = self._original_values[scope]
            if value == "0":
                continue
            self._write(path, value)
        logger.info("ICMP redirects restored to %r", self._original_values)
        self._original_values = None
