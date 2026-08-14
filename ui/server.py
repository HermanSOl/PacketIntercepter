from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Phase1"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask, Response, jsonify, send_from_directory

from detection_engine import AlertHandler, SusAlert
from hostname import extract_hostname
from pkt_capture_parse import LoggedPacket, Packet, PacketLog

STATIC_DIR = Path(__file__).resolve().parent / "static"
POLL_INTERVAL = 0.5


def pkt_fields(pkt: Packet | None) -> dict:
    if pkt is None:
        return {
            "mac_src": None,
            "mac_dst": None,
            "payload_hex": None,
            "payload_len": None,
            "length": None,
            "eth_type": None,
            "ip_ttl": None,
            "ip_id": None,
            "ip_flags": None,
            "ip_proto_num": None,
            "ip_checksum": None,
            "tcp_seq": None,
            "tcp_ack": None,
            "tcp_flags": None,
            "tcp_window": None,
            "hostname": None,
        }
    return {
        "mac_src": pkt.mac_src,
        "mac_dst": pkt.mac_dst,
        "payload_hex": pkt.payload.hex(),
        "payload_len": len(pkt.payload),
        "length": pkt.length,
        "eth_type": pkt.eth_type,
        "ip_ttl": pkt.ip_ttl,
        "ip_id": pkt.ip_id,
        "ip_flags": pkt.ip_flags,
        "ip_proto_num": pkt.ip_proto_num,
        "ip_checksum": pkt.ip_checksum,
        "tcp_seq": pkt.tcp_seq,
        "tcp_ack": pkt.tcp_ack,
        "tcp_flags": pkt.tcp_flags,
        "tcp_window": pkt.tcp_window,
        "hostname": extract_hostname(pkt.protocol, pkt.payload),
    }


def alert_to_dict(alert: SusAlert) -> dict:
    pkt = alert.pkt
    return {
        "id": alert.id,
        "timestamp": alert.timestamp,
        "type": alert.__class__.__name__.removesuffix("Alert"),
        "reason": alert.reason,
        "protocol": pkt.protocol,
        "ip_src": pkt.ip_src,
        "ip_dst": pkt.ip_dst,
        "sport": pkt.sport,
        "dport": pkt.dport,
        **pkt_fields(pkt),
    }


def packet_to_dict(logged: LoggedPacket) -> dict:
    return {
        "id": logged.id,
        "timestamp": logged.timestamp,
        "protocol": logged.protocol,
        "ip_src": logged.ip_src,
        "sport": logged.sport,
        "ip_dst": logged.ip_dst,
        "dport": logged.dport,
        "flagged": bool(logged.alerts),
        "alerts": [
            {"type": a.__class__.__name__.removesuffix("Alert"), "reason": a.reason} for a in logged.alerts
        ],
        # False beyond the flow's FlowTracker budget - see LoggedPacket.pkt's docstring.
        # The frontend uses this to show a reduced detail view rather than blank fields.
        "has_detail": logged.pkt is not None,
        **pkt_fields(logged.pkt),
    }


def _sse_stream(get_items, to_dict):
    def generate():
        last_id_sent = -1
        while True:
            for item in get_items():
                if item.id <= last_id_sent:
                    continue
                yield f"data: {json.dumps(to_dict(item))}\n\n"
                last_id_sent = item.id
            time.sleep(POLL_INTERVAL)

    return Response(generate(), mimetype="text/event-stream")


def create_app(handler: AlertHandler, packet_log: PacketLog) -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    @app.get("/api/alerts")
    def get_alerts():
        # Plain snapshot, mainly for curl/debugging - the page itself uses
        # /api/packets/stream, which already includes flagged packets.
        return jsonify([alert_to_dict(a) for a in handler.get_alerts()])

    @app.get("/api/stream")
    def stream_alerts():
        return _sse_stream(handler.get_alerts, alert_to_dict)

    @app.get("/api/packets")
    def get_packets():
        return jsonify([packet_to_dict(p) for p in packet_log.get_packets()])

    @app.get("/api/packets/stream")
    def stream_packets():
        return _sse_stream(packet_log.get_packets, packet_to_dict)

    return app


def run_ui(
    handler: AlertHandler, packet_log: PacketLog, host: str = "127.0.0.1", port: int = 5000
) -> threading.Thread:
    """Starts the UI's Flask app in a daemon thread against the given (already-live)
    AlertHandler/PacketLog and returns immediately - the caller doesn't need to join it.
    """
    app = create_app(handler, packet_log)
    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, threaded=True, use_reloader=False),
        daemon=True,
    )
    thread.start()
    return thread


def _seed_demo_data(handler: AlertHandler, packet_log: PacketLog) -> None:
    """Fills a handler/packet_log with a mix of flagged and ordinary traffic, so the
    frontend can be worked on without root/an interface/real traffic. Only used by
    `python3 server.py` standalone below - never touched by run_ui() itself.
    """
    from detection_engine import (
        DnsAlert,
        FtpAlert,
        HttpAlert,
        LdapAlert,
        MailAlert,
        RsyncAlert,
        SnmpAlert,
        TelnetAlert,
        WeakTlsAlert,
    )

    def client_hello_with_sni(host: bytes) -> bytes:
        server_name = bytes([0]) + len(host).to_bytes(2, "big") + host
        server_name_list = len(server_name).to_bytes(2, "big") + server_name
        sni_ext = (0x0000).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list
        extensions = len(sni_ext).to_bytes(2, "big") + sni_ext
        body = (
            b"\x03\x03" + b"\x00" * 32  # client_version + random
            + b"\x00"  # empty session_id
            + b"\x00\x02" + b"\x00\x2f"  # one cipher suite
            + b"\x01" + b"\x00"  # null compression
            + extensions
        )
        handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
        return bytes([0x16]) + b"\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    def pkt(sport, dport, ip_dst="93.184.216.34", protocol="TCP", payload=b"", seq=1000, ack=2000, flags="PA"):
        header_len = 54 if protocol == "TCP" else 42  # Ether+IP+TCP vs Ether+IP+UDP, roughly
        return Packet(
            mac_src="aa:bb:cc:dd:ee:01",
            mac_dst="aa:bb:cc:dd:ee:02",
            ip_src="192.168.1.50",
            ip_dst=ip_dst,
            protocol=protocol,
            sport=sport,
            dport=dport,
            payload=payload,
            length=header_len + len(payload),
            eth_type=0x0800,
            ip_ttl=64,
            ip_id=12345,
            ip_flags="DF",
            ip_proto_num=6 if protocol == "TCP" else 17,
            ip_checksum=0xABCD,
            tcp_seq=seq if protocol == "TCP" else None,
            tcp_ack=ack if protocol == "TCP" else None,
            tcp_flags=flags if protocol == "TCP" else "",
            tcp_window=64240 if protocol == "TCP" else None,
        )

    def log(pkt_obj: Packet | None, alerts: list = None, flow_key: tuple = None) -> None:
        if pkt_obj is not None:
            flow_key = (pkt_obj.protocol, pkt_obj.ip_src, pkt_obj.sport, pkt_obj.ip_dst, pkt_obj.dport)
        protocol, ip_src, sport, ip_dst, dport = flow_key
        packet_log.process_packet(LoggedPacket(protocol, ip_src, sport, ip_dst, dport, pkt_obj, alerts=alerts or []))

    http_payload = b"GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"

    flagged = [
        HttpAlert(
            pkt(51000, 80, payload=http_payload),
            "Plaintext HTTP on port 80 - content and any credentials are readable on the wire",
        ),
        FtpAlert(pkt(51001, 21, payload=b"USER admin\r\n"), "FTP USER/PASS sent in cleartext - credentials exposed"),
        TelnetAlert(pkt(51002, 23), "Telnet session - entire session including login is cleartext"),
        DnsAlert(
            pkt(51003, 53, protocol="UDP"), "Unencrypted DNS query - reveals browsing activity and is trivially spoofable"
        ),
        MailAlert(pkt(51004, 143), "Unencrypted IMAP traffic - mail content/credentials exposed"),
        WeakTlsAlert(
            pkt(51005, 443, payload=client_hello_with_sni(b"weak-tls.example.com")),
            "ClientHello proposes TLS 1.0 - deprecated, vulnerable TLS version",
        ),
        LdapAlert(pkt(51006, 389), "LDAP simple bind - directory credentials sent in cleartext"),
        SnmpAlert(
            pkt(51007, 161, protocol="UDP"),
            "SNMP using default community string 'public' - full read/write access to the device if it's writable",
        ),
        RsyncAlert(
            pkt(51008, 873), "Rsync daemon traffic (port 873) - module may allow anonymous access to the full filesystem tree; verify auth is configured"
        ),
    ]

    # Ordinary traffic mixed in - most of it real HTTPS-shaped, so the "all packets,
    # flagged ones highlighted" view actually has something unflagged to show.
    plain_destinations = [
        ("104.20.1.1", 443, "TCP"),
        ("17.253.1.1", 443, "TCP"),
        ("151.101.1.1", 443, "TCP"),
        ("1.1.1.1", 53, "UDP"),
        ("8.8.8.8", 53, "UDP"),
    ]

    sport = 52000
    for _ in range(3):
        for ip_dst, dport, protocol in plain_destinations:
            log(pkt(sport, dport, ip_dst=ip_dst, protocol=protocol, flags="A" if protocol == "TCP" else ""))
            sport += 1

    for alert in flagged:
        handler.process_alert(alert)
        log(alert.pkt, alerts=[alert])

    # A packet beyond its flow's inspection budget - has_detail is False for these.
    log(None, flow_key=("TCP", "192.168.1.50", 52099, "151.101.1.1", 443))


if __name__ == "__main__":
    demo_handler = AlertHandler()
    demo_packet_log = PacketLog()
    _seed_demo_data(demo_handler, demo_packet_log)
    print("UI dev server (demo data) at http://127.0.0.1:5000")
    run_ui(demo_handler, demo_packet_log)
    threading.Event().wait()
