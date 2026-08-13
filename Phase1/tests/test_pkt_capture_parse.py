"""Tests for pkt_capture_parse.py — Packet.sum_from_scapy() and Sniffer.digest()/start()/stop().

Synthetic packets are built with scapy and round-tripped through bytes()/re-parse so that
default fields (e.g. Ether.dst) get resolved the same way they would be for a packet handed
to us by sniff() off the wire, rather than staying as scapy's "unbuilt" None placeholders.
"""
from __future__ import annotations

from unittest.mock import Mock

import pytest
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw

from detection_engine import (
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
from pkt_capture_parse import FlowTracker, Packet, Sniffer


def build(layer):
    """Serialize + re-parse a scapy layer so default fields (MACs, checksums, etc.)
    are resolved exactly like a packet captured off the wire."""
    return Ether(bytes(layer)) if not layer.haslayer(Ether) else layer.__class__(bytes(layer))


class TestPacketSumFromScapy: ## build a packet using scapy, run it through the method, see if matches
    def test_returns_none_when_no_ip_layer(self):
        pkt = build(Ether() / ARP())
        assert Packet.sum_from_scapy(pkt) is None

    def test_tcp_packet(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80) / Raw(b"GET / HTTP/1.1"))
        summary = Packet.sum_from_scapy(pkt)

        assert summary.protocol == "TCP"
        assert summary.ip_src == "10.0.0.1"
        assert summary.ip_dst == "10.0.0.2"
        assert summary.sport == 1111
        assert summary.dport == 80
        assert summary.payload == b"GET / HTTP/1.1"
        assert summary.mac_src == pkt[Ether].src
        assert summary.mac_dst == pkt[Ether].dst

    def test_udp_packet(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53) / Raw(b"dns-query"))
        summary = Packet.sum_from_scapy(pkt)

        assert summary.protocol == "UDP"
        assert summary.sport == 5353
        assert summary.dport == 53
        assert summary.payload == b"dns-query"

    def test_non_tcp_udp_ip_protocol_has_no_ports(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
        summary = Packet.sum_from_scapy(pkt)

        assert summary.protocol == str(pkt[IP].proto)
        assert summary.sport is None
        assert summary.dport is None

    def test_missing_ether_layer_yields_empty_macs(self):
        # A bare IP packet (no Ether) can happen e.g. on loopback / tun interfaces.
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2)
        summary = Packet.sum_from_scapy(pkt)

        assert summary.mac_src == ""
        assert summary.mac_dst == ""

    def test_missing_raw_layer_yields_empty_payload(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2))
        summary = Packet.sum_from_scapy(pkt)

        assert summary.payload == b""


class TestPacketFlowKeyFromScapy:
    def test_returns_none_when_no_ip_layer(self):
        pkt = build(Ether() / ARP())
        assert Packet.flow_key_from_scapy(pkt) is None

    def test_tcp_key_includes_protocol_ips_and_ports(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80))
        assert Packet.flow_key_from_scapy(pkt) == ("TCP", "10.0.0.1", 1111, "10.0.0.2", 80)

    def test_udp_key_includes_protocol_ips_and_ports(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53))
        assert Packet.flow_key_from_scapy(pkt) == ("UDP", "10.0.0.1", 5353, "10.0.0.2", 53)

    def test_reverse_direction_is_a_different_key(self):
        forward = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80))
        reverse = build(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1111))

        assert Packet.flow_key_from_scapy(forward) != Packet.flow_key_from_scapy(reverse)

    def test_non_tcp_udp_key_has_no_ports(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
        assert Packet.flow_key_from_scapy(pkt) == (str(pkt[IP].proto), "10.0.0.1", None, "10.0.0.2", None)


class TestFlowTracker:
    def test_allows_inspection_up_to_the_budget(self):
        tracker = FlowTracker(budget=2)
        key = ("TCP", "10.0.0.1", 1111, "10.0.0.2", 80)

        assert tracker.should_inspect(key) is True
        assert tracker.should_inspect(key) is True

    def test_dismisses_once_budget_is_spent(self):
        tracker = FlowTracker(budget=2)
        key = ("TCP", "10.0.0.1", 1111, "10.0.0.2", 80)

        tracker.should_inspect(key)
        tracker.should_inspect(key)

        assert tracker.should_inspect(key) is False

    def test_tracks_each_flow_key_independently(self):
        tracker = FlowTracker(budget=1)
        a = ("TCP", "10.0.0.1", 1111, "10.0.0.2", 80)
        b = ("TCP", "10.0.0.3", 2222, "10.0.0.4", 443)

        assert tracker.should_inspect(a) is True
        assert tracker.should_inspect(b) is True  # separate budget from a
        assert tracker.should_inspect(a) is False

    def test_clears_when_max_flows_is_reached(self):
        tracker = FlowTracker(budget=1, max_flows=2)
        a = ("TCP", "10.0.0.1", 1111, "10.0.0.2", 80)
        b = ("TCP", "10.0.0.3", 2222, "10.0.0.4", 443)
        c = ("TCP", "10.0.0.5", 3333, "10.0.0.6", 443)

        tracker.should_inspect(a)  # dict now at max_flows=2 after a and b
        tracker.should_inspect(b)
        tracker.should_inspect(c)  # forces a clear before recording c

        # a's dismissal was lost in the clear, so it gets a fresh budget again
        assert tracker.should_inspect(a) is True


class TestSnifferDigest:
    def _tcp_packet(self):
        return build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80) / Raw(b"GET /"))

    def test_returns_none_and_skips_rules_for_non_ip_packet(self):
        rule = Mock()
        on_sus = Mock()
        sniffer = Sniffer(interface="eth0", rules=[rule], on_sus=on_sus)

        result = sniffer.digest(build(Ether() / ARP()))

        assert result is None
        rule.check.assert_not_called()
        on_sus.assert_not_called()

    def test_returns_packet_summary_when_no_rule_fires(self):
        rule = Mock()
        rule.check.return_value = None
        on_sus = Mock()
        sniffer = Sniffer(interface="eth0", rules=[rule], on_sus=on_sus)

        # digest() always returns None (returning the summary would make scapy's
        # sniff(prn=...) auto-print it) - what we can actually verify is that a
        # real Packet got built and handed to the rule.
        result = sniffer.digest(self._tcp_packet())

        assert result is None
        (checked_packet,), _ = rule.check.call_args
        assert isinstance(checked_packet, Packet)
        on_sus.assert_not_called()

    def test_calls_on_sus_when_rule_flags_an_alert(self):
        alert = Mock(name="alert")
        rule = Mock()
        rule.check.return_value = alert
        on_sus = Mock()
        sniffer = Sniffer(interface="eth0", rules=[rule], on_sus=on_sus)

        result = sniffer.digest(self._tcp_packet())

        on_sus.assert_called_once_with(alert)
        assert result is None  # digest() never surfaces the summary itself, only via on_sus

    def test_runs_every_rule_and_reports_each_alert(self):
        quiet_rule = Mock()
        quiet_rule.check.return_value = None
        alert_a, alert_b = Mock(name="a"), Mock(name="b")
        rule_a, rule_b = Mock(), Mock()
        rule_a.check.return_value = alert_a
        rule_b.check.return_value = alert_b
        on_sus = Mock()
        sniffer = Sniffer(interface="eth0", rules=[quiet_rule, rule_a, rule_b], on_sus=on_sus)

        sniffer.digest(self._tcp_packet())

        assert on_sus.call_count == 2
        on_sus.assert_any_call(alert_a)
        on_sus.assert_any_call(alert_b)

    def test_no_rules_means_no_alerts(self):
        on_sus = Mock()
        sniffer = Sniffer(interface="eth0", rules=[], on_sus=on_sus)

        result = sniffer.digest(self._tcp_packet())

        assert result is None
        on_sus.assert_not_called()

    def test_skips_dissection_and_rules_once_a_flows_budget_is_spent(self):
        rule = Mock()
        rule.check.return_value = None
        on_sus = Mock()
        sniffer = Sniffer(
            interface="eth0", rules=[rule], on_sus=on_sus, flow_tracker=FlowTracker(budget=2)
        )

        for _ in range(5):
            sniffer.digest(self._tcp_packet())  # same 5-tuple every time - one flow

        assert rule.check.call_count == 2  # only the first 2 packets of the flow got inspected

    def test_a_different_flow_gets_its_own_budget(self):
        rule = Mock()
        rule.check.return_value = None
        on_sus = Mock()
        sniffer = Sniffer(
            interface="eth0", rules=[rule], on_sus=on_sus, flow_tracker=FlowTracker(budget=1)
        )
        other_flow_packet = build(
            Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=2222, dport=443) / Raw(b"x")
        )

        sniffer.digest(self._tcp_packet())
        sniffer.digest(other_flow_packet)

        assert rule.check.call_count == 2  # each flow got its own budget's-worth of inspection


class TestSnifferLifecycle:
    def test_stop_before_start_does_not_raise(self):
        sniffer = Sniffer(interface="eth0", rules=[], on_sus=Mock())
        sniffer.stop()  # _thread is None; should be a no-op, not AttributeError
        assert sniffer.end is True

    def test_start_spawns_a_daemon_thread_running_start_sniffer(self, monkeypatch):
        started = Mock()
        monkeypatch.setattr(Sniffer, "start_sniffer", started)
        sniffer = Sniffer(interface="eth0", rules=[], on_sus=Mock())

        sniffer.start()
        sniffer._thread.join(timeout=1)

        assert sniffer._thread is not None
        assert sniffer._thread.daemon is True
        started.assert_called_once_with()  # bound as target=self.start_sniffer, so no explicit self arg

    def test_start_sniffer_calls_scapy_sniff_with_expected_kwargs(self, monkeypatch):
        fake_sniff = Mock()
        monkeypatch.setattr("pkt_capture_parse.sniff", fake_sniff)
        sniffer = Sniffer(interface="wlan0", rules=[], on_sus=Mock())

        sniffer.start_sniffer()

        fake_sniff.assert_called_once()
        _, kwargs = fake_sniff.call_args
        assert kwargs["iface"] == "wlan0"
        assert kwargs["prn"] == sniffer.digest
        assert kwargs["store"] is False
        assert kwargs["filter"] is None  # no bpf_filter given - capture everything, as before
        assert callable(kwargs["stop_filter"])
        assert kwargs["stop_filter"](None) is False
        sniffer.end = True
        assert kwargs["stop_filter"](None) is True

    def test_start_sniffer_passes_bpf_filter_through_to_scapy_sniff(self, monkeypatch):
        fake_sniff = Mock()
        monkeypatch.setattr("pkt_capture_parse.sniff", fake_sniff)
        sniffer = Sniffer(interface="wlan0", rules=[], on_sus=Mock(), bpf_filter="ip and host 10.0.0.5")

        sniffer.start_sniffer()

        _, kwargs = fake_sniff.call_args
        assert kwargs["filter"] == "ip and host 10.0.0.5"

    def test_stop_sets_end_and_joins_thread(self, monkeypatch):
        monkeypatch.setattr(Sniffer, "start_sniffer", lambda self: None)
        sniffer = Sniffer(interface="eth0", rules=[], on_sus=Mock())
        sniffer.start()

        sniffer.stop()

        assert sniffer.end is True
        assert not sniffer._thread.is_alive()


class TestScapyPacketTripsDetectionRules:
    """End-to-end check that a real scapy-built packet, parsed by
    Packet.sum_from_scapy(), actually trips the matching detection rule -
    HttpRule/FtpRule are unit-tested against a hand-built Packet in
    test_detection_engine.py; these confirm the two stages chain together."""

    def test_http_request_trips_http_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=80) / Raw(b"GET / HTTP/1.1"))
        summary = Packet.sum_from_scapy(pkt)

        alert = HttpRule().check(summary)

        assert isinstance(alert, HttpAlert)
        assert alert.pkt is summary

    def test_ftp_login_trips_ftp_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=21) / Raw(b"USER admin\r\n"))
        summary = Packet.sum_from_scapy(pkt)

        alert = FtpRule().check(summary)

        assert isinstance(alert, FtpAlert)
        assert alert.pkt is summary

    def test_telnet_session_trips_telnet_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=23) / Raw(b"login: "))
        summary = Packet.sum_from_scapy(pkt)

        alert = TelnetRule().check(summary)

        assert isinstance(alert, TelnetAlert)
        assert alert.pkt is summary

    def test_dns_query_trips_dns_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=54321, dport=53) / Raw(b"dns-query"))
        summary = Packet.sum_from_scapy(pkt)

        alert = DnsRule().check(summary)

        assert isinstance(alert, DnsAlert)
        assert alert.pkt is summary

    def test_smtp_traffic_trips_mail_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=25) / Raw(b"MAIL FROM:<a@b.com>"))
        summary = Packet.sum_from_scapy(pkt)

        alert = MailRule().check(summary)

        assert isinstance(alert, MailAlert)
        assert alert.pkt is summary

    def test_tls_1_0_client_hello_trips_weak_tls_rule(self):
        # content type 0x16 (Handshake), record version, record length,
        tls_payload = b"\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x01" + b"\x00" * 32
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=443) / Raw(tls_payload))
        summary = Packet.sum_from_scapy(pkt)

        alert = WeakTlsRule().check(summary)

        assert isinstance(alert, WeakTlsAlert)
        assert alert.pkt is summary

    def test_pop3_traffic_trips_mail_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=110) / Raw(b"USER admin\r\n"))
        summary = Packet.sum_from_scapy(pkt)

        alert = MailRule().check(summary)

        assert isinstance(alert, MailAlert)
        assert alert.pkt is summary

    def test_imap_traffic_trips_mail_rule(self):
        pkt = build(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=143) / Raw(b"a LOGIN admin pass\r\n"))
        summary = Packet.sum_from_scapy(pkt)

        alert = MailRule().check(summary)

        assert isinstance(alert, MailAlert)
        assert alert.pkt is summary
