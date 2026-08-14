"""Tests for hostname.py's HTTP Host / TLS SNI extraction."""
from __future__ import annotations

from hostname import extract_hostname


def client_hello(
    host: bytes | None = b"example.com",
    version: bytes = b"\x03\x03",
    include_sni_extension: bool = True,
    session_id: bytes = b"",
    truncate_to: int | None = None,
) -> bytes:
    """Hand-builds a structurally real ClientHello (+ optional SNI extension),
    matching the byte layout documented in hostname.py's module docstring."""
    if include_sni_extension:
        server_name = bytes([0]) + len(host).to_bytes(2, "big") + host
        server_name_list = len(server_name).to_bytes(2, "big") + server_name
        sni_ext = (0x0000).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list
        extensions = len(sni_ext).to_bytes(2, "big") + sni_ext
    else:
        extensions = b"\x00\x00"  # extensions_len = 0, no extensions

    body = (
        version
        + b"\x00" * 32  # random
        + bytes([len(session_id)]) + session_id
        + b"\x00\x02" + b"\x00\x2f"  # cipher_suites_len(2) + one cipher suite
        + b"\x01" + b"\x00"  # compression_methods_len(1) + null compression
        + extensions
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    record = bytes([0x16]) + b"\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record[:truncate_to] if truncate_to is not None else record


class TestHttpHost:
    def test_extracts_host_header(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n"
        assert extract_hostname("TCP", payload) == "example.com"

    def test_extracts_host_with_port(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        assert extract_hostname("TCP", payload) == "example.com:8080"

    def test_no_host_header_returns_none(self):
        payload = b"GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n"
        assert extract_hostname("TCP", payload) is None

    def test_ignores_udp_payloads(self):
        payload = b"Host: example.com\r\n"
        assert extract_hostname("UDP", payload) is None

    def test_empty_payload_returns_none(self):
        assert extract_hostname("TCP", b"") is None


class TestTlsSni:
    def test_extracts_sni_hostname(self):
        payload = client_hello(host=b"weak-tls.example.com")
        assert extract_hostname("TCP", payload) == "weak-tls.example.com"

    def test_not_a_handshake_record_returns_none(self):
        payload = b"\x17" + b"\x00" * 20  # 0x17 = application data, not handshake
        assert extract_hostname("TCP", payload) is None

    def test_not_a_client_hello_returns_none(self):
        # A handshake record whose message type isn't ClientHello (e.g. ServerHello=0x02)
        payload = bytes([0x16]) + b"\x03\x01" + b"\x00\x04" + bytes([0x02]) + b"\x00\x00\x00"
        assert extract_hostname("TCP", payload) is None

    def test_client_hello_without_sni_extension_returns_none(self):
        payload = client_hello(include_sni_extension=False)
        assert extract_hostname("TCP", payload) is None

    def test_truncated_client_hello_returns_none_not_an_exception(self):
        # Simulates a ClientHello split across TCP segments, common since WeakTlsRule
        # only ever sees the first few packets of a flow (FlowTracker's budget).
        payload = client_hello(host=b"example.com", truncate_to=20)
        assert extract_hostname("TCP", payload) is None

    def test_non_tls_garbage_returns_none_not_an_exception(self):
        payload = bytes([0x16]) + bytes(range(256)) * 4
        assert extract_hostname("TCP", payload) is None

    def test_http_takes_priority_over_tls_when_somehow_both_match(self):
        # Not a realistic packet, just confirms extract_hostname() tries HTTP first.
        payload = b"Host: from-http.example.com\r\n" + client_hello(host=b"from-tls.example.com")
        assert extract_hostname("TCP", payload) == "from-http.example.com"
