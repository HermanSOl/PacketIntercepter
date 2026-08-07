"""Tests for detection_engine.py — HttpRule, FtpRule, and AlertHandler."""
from __future__ import annotations

from detection_engine import AlertHandler, FtpAlert, FtpRule, HttpAlert, HttpRule
from pkt_capture_parse import Packet


def make_packet(protocol="TCP", sport=1111, dport=80, payload=b""):
    return Packet(
        mac_src="aa:aa:aa:aa:aa:aa",
        mac_dst="bb:bb:bb:bb:bb:bb",
        ip_src="10.0.0.1",
        ip_dst="10.0.0.2",
        protocol=protocol,
        sport=sport,
        dport=dport,
        payload=payload,
    )


class TestHttpRule:
    def test_flags_tcp_traffic_to_port_80(self):
        pkt = make_packet(dport=80)
        alert = HttpRule().check(pkt)

        assert isinstance(alert, HttpAlert)
        assert alert.pkt is pkt
        assert alert.reason

    def test_flags_tcp_traffic_from_port_80(self):
        # response packets have sport=80 rather than dport=80
        pkt = make_packet(sport=80, dport=54321)
        assert isinstance(HttpRule().check(pkt), HttpAlert)

    def test_ignores_tcp_traffic_on_other_ports(self):
        pkt = make_packet(sport=1111, dport=443)
        assert HttpRule().check(pkt) is None

    def test_ignores_non_tcp_traffic_on_port_80(self):
        pkt = make_packet(protocol="UDP", dport=80)
        assert HttpRule().check(pkt) is None


class TestFtpRule:
    def test_flags_user_command_on_control_port(self):
        pkt = make_packet(dport=21, payload=b"USER admin\r\n")
        alert = FtpRule().check(pkt)

        assert isinstance(alert, FtpAlert)
        assert alert.pkt is pkt

    def test_flags_pass_command_on_control_port(self):
        pkt = make_packet(dport=21, payload=b"PASS hunter2\r\n")
        assert isinstance(FtpRule().check(pkt), FtpAlert)

    def test_ignores_control_port_traffic_without_credentials(self):
        pkt = make_packet(dport=21, payload=b"220 Welcome\r\n")
        assert FtpRule().check(pkt) is None

    def test_ignores_credential_marker_on_non_control_port(self):
        # e.g. the FTP data channel, or a coincidental payload on another port
        pkt = make_packet(dport=20, payload=b"USER admin\r\n")
        assert FtpRule().check(pkt) is None

    def test_ignores_udp_traffic_on_control_port(self):
        pkt = make_packet(protocol="UDP", dport=21, payload=b"USER admin\r\n")
        assert FtpRule().check(pkt) is None


class TestAlertHandler:
    def test_process_alert_stores_it(self):
        handler = AlertHandler()
        alert = HttpAlert(make_packet(), "test reason")

        handler.process_alert(alert)

        assert handler.get_alerts() == [alert]

    def test_get_alerts_returns_a_copy(self):
        handler = AlertHandler()
        handler.process_alert(HttpAlert(make_packet(), "reason"))

        snapshot = handler.get_alerts()
        snapshot.append("not a real alert")

        assert len(handler.get_alerts()) == 1

    def test_maxlen_evicts_oldest_alert(self):
        handler = AlertHandler(maxlen=2)
        first = HttpAlert(make_packet(), "first")
        second = HttpAlert(make_packet(), "second")
        third = HttpAlert(make_packet(), "third")

        for alert in (first, second, third):
            handler.process_alert(alert)

        assert handler.get_alerts() == [second, third]
