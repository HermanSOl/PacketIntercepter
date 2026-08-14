"""Tests for server.py - alert_to_dict()'s field mapping and the Flask routes."""
from __future__ import annotations

from server import alert_to_dict, create_app  # imported first - fixes up sys.path for Phase1's modules below

from detection_engine import AlertHandler, HttpAlert
from pkt_capture_parse import Packet


def make_packet(**overrides):
    fields = dict(
        mac_src="aa:bb:cc:dd:ee:01",
        mac_dst="aa:bb:cc:dd:ee:02",
        ip_src="192.168.1.50",
        ip_dst="93.184.216.34",
        protocol="TCP",
        sport=51000,
        dport=80,
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    fields.update(overrides)
    return Packet(**fields)


class TestAlertToDict:
    def test_includes_id_and_timestamp(self):
        handler = AlertHandler()
        alert = HttpAlert(make_packet(), "reason")
        handler.process_alert(alert)

        result = alert_to_dict(alert)

        assert result["id"] == 0
        assert result["timestamp"] == alert.timestamp

    def test_includes_header_detail_fields(self):
        pkt = make_packet(length=100, ip_ttl=64, tcp_flags="PA")
        alert = HttpAlert(pkt, "reason")

        result = alert_to_dict(alert)

        assert result["length"] == 100
        assert result["ip_ttl"] == 64
        assert result["tcp_flags"] == "PA"

    def test_includes_extracted_hostname(self):
        alert = HttpAlert(make_packet(payload=b"GET / HTTP/1.1\r\nHost: sneaky.example\r\n\r\n"), "reason")

        result = alert_to_dict(alert)

        assert result["hostname"] == "sneaky.example"

    def test_hostname_is_none_when_not_present(self):
        alert = HttpAlert(make_packet(payload=b"no host header here"), "reason")

        result = alert_to_dict(alert)

        assert result["hostname"] is None


class TestRoutes:
    def test_index_serves_the_page(self):
        client = create_app(AlertHandler()).test_client()

        response = client.get("/")

        assert response.status_code == 200
        assert b"Flagged Packets" in response.data

    def test_static_files_are_served(self):
        client = create_app(AlertHandler()).test_client()

        assert client.get("/app.js").status_code == 200
        assert client.get("/style.css").status_code == 200

    def test_api_alerts_returns_processed_alerts_as_json(self):
        handler = AlertHandler()
        handler.process_alert(HttpAlert(make_packet(), "plaintext HTTP"))
        client = create_app(handler).test_client()

        response = client.get("/api/alerts")

        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 1
        assert body[0]["reason"] == "plaintext HTTP"
        assert body[0]["hostname"] == "example.com"

    def test_api_alerts_empty_when_no_alerts_yet(self):
        client = create_app(AlertHandler()).test_client()

        response = client.get("/api/alerts")

        assert response.get_json() == []
