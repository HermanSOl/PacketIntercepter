from __future__ import annotations

from unittest.mock import Mock

import pytest
from scapy.all import ARP, Ether

from arp_spoof import ArpSpoofer, MacResolutionError, SpoofSendError


def make_spoofer(**overrides):
    kwargs = dict(
        interface="eth0",
        target_ip="10.0.0.5",
        gateway_ip="10.0.0.1",
        target_mac="aa:aa:aa:aa:aa:aa",
        gateway_mac="bb:bb:bb:bb:bb:bb",
    )
    kwargs.update(overrides)
    return ArpSpoofer(**kwargs)


class TestResolveMac:
    def test_returns_mac_from_arp_reply(self, monkeypatch):
        reply = Ether(src="cc:cc:cc:cc:cc:cc") / ARP(psrc="10.0.0.5", hwsrc="cc:cc:cc:cc:cc:cc")
        monkeypatch.setattr("arp_spoof.srp", Mock(return_value=([(Mock(), reply)], [])))
        spoofer = make_spoofer(target_mac=None)

        mac = spoofer.resolve_mac("10.0.0.5")

        assert mac == "cc:cc:cc:cc:cc:cc"

    def test_sends_arp_request_with_expected_shape_and_kwargs(self, monkeypatch):
        reply = Ether(src="cc:cc:cc:cc:cc:cc") / ARP()
        fake_srp = Mock(return_value=([(Mock(), reply)], []))
        monkeypatch.setattr("arp_spoof.srp", fake_srp)
        spoofer = make_spoofer(target_mac=None)

        spoofer.resolve_mac("10.0.0.5")

        fake_srp.assert_called_once()
        args, kwargs = fake_srp.call_args
        sent = args[0]
        assert sent[ARP].op == 1  # who-has request, not a reply
        assert sent[ARP].pdst == "10.0.0.5"
        assert sent[Ether].dst == "ff:ff:ff:ff:ff:ff"  # broadcast
        assert kwargs["iface"] == "eth0"
        assert kwargs["timeout"] == 3
        assert kwargs["retry"] == 2
        assert kwargs["verbose"] is False

    def test_raises_mac_resolution_error_when_no_reply(self, monkeypatch):
        monkeypatch.setattr("arp_spoof.srp", Mock(return_value=([], [])))
        spoofer = make_spoofer(target_mac=None)

        with pytest.raises(MacResolutionError):
            spoofer.resolve_mac("10.0.0.5")

    def test_wraps_srp_failure_in_mac_resolution_error(self, monkeypatch):
        original = OSError("no such device")
        monkeypatch.setattr("arp_spoof.srp", Mock(side_effect=original))
        spoofer = make_spoofer(target_mac=None)

        with pytest.raises(MacResolutionError) as exc_info:
            spoofer.resolve_mac("10.0.0.5")

        assert exc_info.value.__cause__ is original


class TestSend:
    def test_builds_and_sends_spoofed_arp_reply(self, monkeypatch):
        fake_sendp = Mock()
        monkeypatch.setattr("arp_spoof.sendp", fake_sendp)
        spoofer = make_spoofer()
        spoofer._own_mac = "ee:ee:ee:ee:ee:ee"

        spoofer.send(dst_mac="aa:aa:aa:aa:aa:aa", spoofed_ip="10.0.0.1", real_dst_ip="10.0.0.5")

        fake_sendp.assert_called_once()
        args, kwargs = fake_sendp.call_args
        pkt = args[0]
        assert pkt[Ether].dst == "aa:aa:aa:aa:aa:aa"
        assert pkt[ARP].op == 2  # reply, not request
        assert pkt[ARP].psrc == "10.0.0.1"  # the lie: "10.0.0.1 is at ..."
        assert pkt[ARP].pdst == "10.0.0.5"
        assert pkt[ARP].hwdst == "aa:aa:aa:aa:aa:aa"
        assert pkt[ARP].hwsrc == "ee:ee:ee:ee:ee:ee"  # defaults to our own MAC
        assert kwargs["iface"] == "eth0"
        assert kwargs["verbose"] is False

    def test_explicit_src_mac_overrides_own_mac(self, monkeypatch):
        fake_sendp = Mock()
        monkeypatch.setattr("arp_spoof.sendp", fake_sendp)
        spoofer = make_spoofer()
        spoofer._own_mac = "ee:ee:ee:ee:ee:ee"

        spoofer.send(
            dst_mac="aa:aa:aa:aa:aa:aa",
            spoofed_ip="10.0.0.1",
            real_dst_ip="10.0.0.5",
            src_mac="ff:ff:ff:ff:ff:ff",
        )

        pkt = fake_sendp.call_args[0][0]
        assert pkt[ARP].hwsrc == "ff:ff:ff:ff:ff:ff"  # used for restore(): the real owner's MAC

    def test_wraps_sendp_failure_in_spoof_send_error(self, monkeypatch):
        original = OSError("network is down")
        monkeypatch.setattr("arp_spoof.sendp", Mock(side_effect=original))
        spoofer = make_spoofer()
        spoofer._own_mac = "ee:ee:ee:ee:ee:ee"

        with pytest.raises(SpoofSendError) as exc_info:
            spoofer.send(dst_mac="aa:aa:aa:aa:aa:aa", spoofed_ip="10.0.0.1", real_dst_ip="10.0.0.5")

        assert exc_info.value.__cause__ is original


class TestPoison:
    def test_poisons_target_with_gateways_identity(self):
        spoofer = make_spoofer()
        spoofer.send = Mock()

        spoofer.poison()

        spoofer.send.assert_any_call(dst_mac="aa:aa:aa:aa:aa:aa", spoofed_ip="10.0.0.1", real_dst_ip="10.0.0.5")

    def test_poisons_gateway_with_targets_identity(self):
        spoofer = make_spoofer()
        spoofer.send = Mock()

        spoofer.poison()

        spoofer.send.assert_any_call(dst_mac="bb:bb:bb:bb:bb:bb", spoofed_ip="10.0.0.5", real_dst_ip="10.0.0.1")

    def test_sends_exactly_two_packets(self):
        spoofer = make_spoofer()
        spoofer.send = Mock()

        spoofer.poison()

        assert spoofer.send.call_count == 2
