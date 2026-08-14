from __future__ import annotations

import re

_HTTP_HOST_RE = re.compile(rb"[Hh]ost:[ \t]*([^\r\n]+)")

_TLS_HANDSHAKE_RECORD = 0x16
_TLS_CLIENT_HELLO = 0x01
_SNI_EXTENSION_TYPE = 0x0000
_SNI_HOST_NAME_TYPE = 0x00


def extract_hostname(protocol: str, payload: bytes) -> str | None:
    if protocol != "TCP" or not payload:
        return None
    return _http_host(payload) or _tls_sni(payload)


def _http_host(payload: bytes) -> str | None:
    match = _HTTP_HOST_RE.search(payload)
    if not match:
        return None
    return match.group(1).decode("ascii", errors="replace").strip()


def _tls_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 5 or payload[0] != _TLS_HANDSHAKE_RECORD:
            return None
        pos = 5
        if pos + 4 > len(payload) or payload[pos] != _TLS_CLIENT_HELLO:
            return None
        pos += 4

        pos += 2 + 32  # client_version + random
        if pos >= len(payload):
            return None
        pos += 1 + payload[pos]  # session_id_len + session_id

        if pos + 2 > len(payload):
            return None
        cipher_suites_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len

        if pos >= len(payload):
            return None
        pos += 1 + payload[pos]  # compression_methods_len + compression_methods

        if pos + 2 > len(payload):
            return None
        extensions_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        extensions_end = min(pos + extensions_len, len(payload))

        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            ext_data_start = pos + 4
            if ext_type == _SNI_EXTENSION_TYPE:
                return _parse_server_name_extension(payload[ext_data_start:ext_data_start + ext_len])
            pos = ext_data_start + ext_len

        return None
    except (IndexError, ValueError):
        return None


def _parse_server_name_extension(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    name_type = data[2]
    name_len = int.from_bytes(data[3:5], "big")
    if name_type != _SNI_HOST_NAME_TYPE:
        return None
    name = data[5:5 + name_len]
    if len(name) != name_len:
        return None
    return name.decode("ascii", errors="replace")
