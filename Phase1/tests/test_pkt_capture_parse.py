"""Tests for pkt_capture_parse.py — Packet.sum_from_scapy() and Sniffer.digest()/start()/stop().

Synthetic packets are built with scapy and round-tripped through bytes()/re-parse so that
default fields (e.g. Ether.dst) get resolved the same way they would be for a packet handed
to us by sniff() off the wire, rather than staying as scapy's "unbuilt" None placeholders.
"""
from __future__ import annotations

from unittest.mock import Mock

import pytest
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw

from pkt_capture_parse import Packet, Sniffer


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

        result = sniffer.digest(self._tcp_packet())

        assert isinstance(result, Packet)
        rule.check.assert_called_once_with(result)
        on_sus.assert_not_called()

    def test_calls_on_sus_when_rule_flags_an_alert(self):
        alert = Mock(name="alert")
        rule = Mock()
        rule.check.return_value = alert
        on_sus = Mock()
        sniffer = Sniffer(interface="eth0", rules=[rule], on_sus=on_sus)

        result = sniffer.digest(self._tcp_packet())

        on_sus.assert_called_once_with(alert)
        assert result is not None

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

        assert isinstance(result, Packet)
        on_sus.assert_not_called()


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
        assert callable(kwargs["stop_filter"])
        assert kwargs["stop_filter"](None) is False
        sniffer.end = True
        assert kwargs["stop_filter"](None) is True

    def test_stop_sets_end_and_joins_thread(self, monkeypatch):
        monkeypatch.setattr(Sniffer, "start_sniffer", lambda self: None)
        sniffer = Sniffer(interface="eth0", rules=[], on_sus=Mock())
        sniffer.start()

        sniffer.stop()

        assert sniffer.end is True
        assert not sniffer._thread.is_alive()
