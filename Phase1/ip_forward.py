from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


class IpForwardError(Exception):
    """Raised when the IPv4 forwarding sysctl can't be read or written."""


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
