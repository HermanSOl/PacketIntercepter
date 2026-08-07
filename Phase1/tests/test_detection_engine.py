"""Tests for detection_engine.py — HttpRule, FtpRule, and AlertHandler."""
from __future__ import annotations

from detection_engine import (
    AlertHandler,
    DnsAlert,
    DnsRule,
    FtpAlert,
    FtpRule,
    HttpAlert,
    HttpRule,
    MailAlert,
    MailRule,
    TelnetAlert,
    TelnetRule,
    WeakTlsAlert,
    WeakTlsRule,
)
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


def make_tls_record(handshake_type=0x01, version=b"\x03\x01", content_type=0x16):
    """Builds the fixed-position bytes WeakTlsRule reads: record header,
    handshake header, then the client/server version field."""
    record_version = b"\x03\x01"
    record_length = b"\x00\x2f"
    handshake_length = b"\x00\x00\x2b"
    return bytes([content_type]) + record_version + record_length + bytes([handshake_type]) + handshake_length + version


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


class TestTelnetRule:
    def test_flags_tcp_traffic_to_port_23(self):
        pkt = make_packet(dport=23)
        alert = TelnetRule().check(pkt)

        assert isinstance(alert, TelnetAlert)
        assert alert.pkt is pkt

    def test_flags_tcp_traffic_from_port_23(self):
        pkt = make_packet(sport=23, dport=54321)
        assert isinstance(TelnetRule().check(pkt), TelnetAlert)

    def test_ignores_tcp_traffic_on_other_ports(self):
        pkt = make_packet(sport=1111, dport=443)
        assert TelnetRule().check(pkt) is None

    def test_ignores_non_tcp_traffic_on_port_23(self):
        pkt = make_packet(protocol="UDP", dport=23)
        assert TelnetRule().check(pkt) is None


class TestDnsRule:
    def test_flags_udp_traffic_to_port_53(self):
        pkt = make_packet(protocol="UDP", dport=53)
        alert = DnsRule().check(pkt)

        assert isinstance(alert, DnsAlert)
        assert alert.pkt is pkt

    def test_flags_udp_traffic_from_port_53(self):
        pkt = make_packet(protocol="UDP", sport=53, dport=54321)
        assert isinstance(DnsRule().check(pkt), DnsAlert)

    def test_ignores_udp_traffic_on_other_ports(self):
        pkt = make_packet(protocol="UDP", sport=1111, dport=443)
        assert DnsRule().check(pkt) is None

    def test_ignores_tcp_traffic_on_port_53(self):
        # DNS-over-TCP exists but isn't covered by this rule
        pkt = make_packet(protocol="TCP", dport=53)
        assert DnsRule().check(pkt) is None


class TestMailRule:
    def test_flags_smtp_traffic_on_port_25(self):
        pkt = make_packet(dport=25)
        alert = MailRule().check(pkt)

        assert isinstance(alert, MailAlert)
        assert alert.pkt is pkt
        assert "SMTP" in alert.reason

    def test_flags_pop3_traffic_on_port_110(self):
        pkt = make_packet(dport=110)
        alert = MailRule().check(pkt)

        assert isinstance(alert, MailAlert)
        assert "POP3" in alert.reason

    def test_flags_imap_traffic_on_port_143(self):
        pkt = make_packet(dport=143)
        alert = MailRule().check(pkt)

        assert isinstance(alert, MailAlert)
        assert "IMAP" in alert.reason

    def test_flags_traffic_when_mail_port_is_source(self):
        pkt = make_packet(sport=25, dport=54321)
        assert isinstance(MailRule().check(pkt), MailAlert)

    def test_ignores_tcp_traffic_on_other_ports(self):
        pkt = make_packet(sport=1111, dport=443)
        assert MailRule().check(pkt) is None

    def test_ignores_udp_traffic_on_mail_ports(self):
        pkt = make_packet(protocol="UDP", dport=25)
        assert MailRule().check(pkt) is None


class TestWeakTlsRule:
    def test_flags_client_hello_proposing_tls_1_0(self):
        pkt = make_packet(payload=make_tls_record(handshake_type=0x01, version=b"\x03\x01"))
        alert = WeakTlsRule().check(pkt)

        assert isinstance(alert, WeakTlsAlert)
        assert alert.pkt is pkt
        assert "ClientHello" in alert.reason
        assert "TLS 1.0" in alert.reason

    def test_flags_server_hello_proposing_tls_1_1(self):
        pkt = make_packet(payload=make_tls_record(handshake_type=0x02, version=b"\x03\x02"))
        alert = WeakTlsRule().check(pkt)

        assert isinstance(alert, WeakTlsAlert)
        assert "ServerHello" in alert.reason
        assert "TLS 1.1" in alert.reason

    def test_ignores_modern_tls_version(self):
        # TLS 1.2/1.3 clients set this field to 0x0303 - not weak, should pass through
        pkt = make_packet(payload=make_tls_record(handshake_type=0x01, version=b"\x03\x03"))
        assert WeakTlsRule().check(pkt) is None

    def test_ignores_non_hello_handshake_message(self):
        # e.g. Certificate (0x0b) - a handshake message, but not a Hello, so it
        # has no client/server version field at this offset
        pkt = make_packet(payload=make_tls_record(handshake_type=0x0b, version=b"\x03\x01"))
        assert WeakTlsRule().check(pkt) is None

    def test_ignores_non_handshake_content_type(self):
        # e.g. ApplicationData (0x17) - encrypted traffic after the handshake completes
        pkt = make_packet(payload=make_tls_record(handshake_type=0x01, version=b"\x03\x01", content_type=0x17))
        assert WeakTlsRule().check(pkt) is None

    def test_ignores_udp_traffic(self):
        pkt = make_packet(protocol="UDP", payload=make_tls_record())
        assert WeakTlsRule().check(pkt) is None

    def test_ignores_payload_too_short_to_contain_a_version_field(self):
        pkt = make_packet(payload=b"\x16\x03\x01")
        assert WeakTlsRule().check(pkt) is None


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
