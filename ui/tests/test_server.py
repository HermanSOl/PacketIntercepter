"""Tests for server.py - alert_to_dict()/packet_to_dict()'s field mapping and the
Flask routes."""
from __future__ import annotations

from server import alert_to_dict, create_app, packet_to_dict  # fixes up sys.path for Phase1's modules below

from detection_engine import AlertHandler, HttpAlert
from pkt_capture_parse import LoggedPacket, Packet, PacketLog


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


def make_app(handler=None, packet_log=None):
    return create_app(handler or AlertHandler(), packet_log or PacketLog())


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


class TestPacketToDict:
    def test_plain_packet_is_not_flagged(self):
        log = PacketLog()
        logged = LoggedPacket("TCP", "10.0.0.1", 1111, "10.0.0.2", 80, pkt=make_packet())
        log.process_packet(logged)

        result = packet_to_dict(logged)

        assert result["flagged"] is False
        assert result["alerts"] == []

    def test_flagged_packet_includes_its_alerts(self):
        log = PacketLog()
        pkt = make_packet()
        alert = HttpAlert(pkt, "plaintext HTTP")
        logged = LoggedPacket("TCP", "10.0.0.1", 1111, "10.0.0.2", 80, pkt=pkt, alerts=[alert])
        log.process_packet(logged)

        result = packet_to_dict(logged)

        assert result["flagged"] is True
        assert result["alerts"] == [{"type": "Http", "reason": "plaintext HTTP"}]

    def test_has_detail_true_when_pkt_present(self):
        logged = LoggedPacket("TCP", "10.0.0.1", 1111, "10.0.0.2", 80, pkt=make_packet())
        result = packet_to_dict(logged)

        assert result["has_detail"] is True
        assert result["length"] == logged.pkt.length

    def test_has_detail_false_and_blank_fields_beyond_budget(self):
        # pkt=None - a packet logged past its flow's FlowTracker budget
        logged = LoggedPacket("TCP", "10.0.0.1", 1111, "10.0.0.2", 80, pkt=None)

        result = packet_to_dict(logged)

        assert result["has_detail"] is False
        assert result["length"] is None
        assert result["hostname"] is None
        # identity still present even without full detail
        assert result["protocol"] == "TCP"
        assert result["ip_src"] == "10.0.0.1"


class TestRoutes:
    def test_index_serves_the_page(self):
        client = make_app().test_client()

        response = client.get("/")

        assert response.status_code == 200
        assert b"Packet Capture" in response.data

    def test_static_files_are_served(self):
        client = make_app().test_client()

        assert client.get("/app.js").status_code == 200
        assert client.get("/style.css").status_code == 200

    def test_api_alerts_returns_processed_alerts_as_json(self):
        handler = AlertHandler()
        handler.process_alert(HttpAlert(make_packet(), "plaintext HTTP"))
        client = make_app(handler=handler).test_client()

        response = client.get("/api/alerts")

        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 1
        assert body[0]["reason"] == "plaintext HTTP"
        assert body[0]["hostname"] == "example.com"

    def test_api_alerts_empty_when_no_alerts_yet(self):
        client = make_app().test_client()

        assert client.get("/api/alerts").get_json() == []

    def test_api_packets_returns_logged_packets_as_json(self):
        packet_log = PacketLog()
        packet_log.process_packet(LoggedPacket("TCP", "10.0.0.1", 1111, "10.0.0.2", 80, pkt=make_packet()))
        client = make_app(packet_log=packet_log).test_client()

        response = client.get("/api/packets")

        assert response.status_code == 200
        body = response.get_json()
        assert len(body) == 1
        assert body[0]["protocol"] == "TCP"
        assert body[0]["flagged"] is False

    def test_api_packets_includes_flagged_packets(self):
        packet_log = PacketLog()
        pkt = make_packet()
        alert = HttpAlert(pkt, "plaintext HTTP")
        packet_log.process_packet(LoggedPacket("TCP", "10.0.0.1", 1111, "10.0.0.2", 80, pkt=pkt, alerts=[alert]))
        client = make_app(packet_log=packet_log).test_client()

        body = client.get("/api/packets").get_json()

        assert body[0]["flagged"] is True
        assert body[0]["alerts"][0]["reason"] == "plaintext HTTP"

    def test_api_packets_empty_when_no_packets_yet(self):
        client = make_app().test_client()

        assert client.get("/api/packets").get_json() == []
