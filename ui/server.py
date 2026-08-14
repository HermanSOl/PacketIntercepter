from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Phase1"))

from flask import Flask, Response, jsonify, send_from_directory  

from detection_engine import AlertHandler, SusAlert 

STATIC_DIR = Path(__file__).resolve().parent / "static"

POLL_INTERVAL = 0.5


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
        "mac_src": pkt.mac_src,
        "mac_dst": pkt.mac_dst,
        "payload_hex": pkt.payload.hex(),
        "payload_len": len(pkt.payload),
    }


def create_app(handler: AlertHandler) -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    @app.get("/api/alerts")
    def get_alerts():
        # Plain snapshot, mainly for curl/debugging - the page itself gets its
        # data (initial backlog + live updates) from /api/stream alone.
        return jsonify([alert_to_dict(a) for a in handler.get_alerts()])

    @app.get("/api/stream")
    def stream():
        def generate():
            last_id_sent = -1
            while True:
                for alert in handler.get_alerts():
                    if alert.id <= last_id_sent:
                        continue
                    yield f"data: {json.dumps(alert_to_dict(alert))}\n\n"
                    last_id_sent = alert.id
                time.sleep(POLL_INTERVAL)

        return Response(generate(), mimetype="text/event-stream")

    return app


def run_ui(handler: AlertHandler, host: str = "127.0.0.1", port: int = 5000) -> threading.Thread:
    """Starts the UI's Flask app in a daemon thread against the given (already-live)
    AlertHandler and returns immediately - the caller doesn't need to join it.
    """
    app = create_app(handler)
    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, threaded=True, use_reloader=False),
        daemon=True,
    )
    thread.start()
    return thread


def _seed_demo_alerts(handler: AlertHandler) -> None:
    """Fills a handler with a few fake alerts spanning every rule type, so the
    frontend can be worked on without root/an interface/real traffic. Only used
    by `python3 server.py` standalone below - never touched by run_ui() itself.
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
    from pkt_capture_parse import Packet

    def pkt(sport, dport, protocol="TCP", payload=b""):
        return Packet(
            mac_src="aa:bb:cc:dd:ee:01",
            mac_dst="aa:bb:cc:dd:ee:02",
            ip_src="192.168.1.50",
            ip_dst="93.184.216.34",
            protocol=protocol,
            sport=sport,
            dport=dport,
            payload=payload,
        )

    demo_alerts = [
        HttpAlert(pkt(51000, 80), "Plaintext HTTP on port 80 - content and any credentials are readable on the wire"),
        FtpAlert(pkt(51001, 21, payload=b"USER admin\r\n"), "FTP USER/PASS sent in cleartext - credentials exposed"),
        TelnetAlert(pkt(51002, 23), "Telnet session - entire session including login is cleartext"),
        DnsAlert(pkt(51003, 53, protocol="UDP"), "Unencrypted DNS query - reveals browsing activity and is trivially spoofable"),
        MailAlert(pkt(51004, 143), "Unencrypted IMAP traffic - mail content/credentials exposed"),
        WeakTlsAlert(pkt(51005, 443), "ClientHello proposes TLS 1.0 - deprecated, vulnerable TLS version"),
        LdapAlert(pkt(51006, 389), "LDAP simple bind - directory credentials sent in cleartext"),
        SnmpAlert(pkt(51007, 161, protocol="UDP"), "SNMP using default community string 'public' - full read/write access to the device if it's writable"),
        RsyncAlert(pkt(51008, 873), "Rsync daemon traffic (port 873) - module may allow anonymous access to the full filesystem tree; verify auth is configured"),
    ]
    for alert in demo_alerts:
        handler.process_alert(alert)


if __name__ == "__main__":
    demo_handler = AlertHandler()
    _seed_demo_alerts(demo_handler)
    print("UI dev server (demo data) at http://127.0.0.1:5000")
    run_ui(demo_handler)
    threading.Event().wait()
