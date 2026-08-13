from __future__ import annotations

import logging
from collections import Counter
from unittest.mock import Mock

import pytest
from scapy.all import ARP, Ether

from arp_spoof import ArpSpoofer, ArpSpoofError, MacResolutionError, SpoofSendError


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
        assert kwargs["timeout"] == ArpSpoofer.RESOLVE_TIMEOUT
        assert kwargs["retry"] == ArpSpoofer.RESOLVE_RETRY
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

    def test_packet_survives_real_wire_serialization(self, monkeypatch):
        # Every other test in this class inspects the pre-serialization packet
        # object. This one forces bytes(pkt) - same as scapy does right before
        # putting it on the wire - and re-parses the result, so a field that
        # can't actually pack (bad MAC/IP string, wrong type, etc.) fails here
        # instead of surfacing for the first time against a real interface.
        captured = {}
        monkeypatch.setattr("arp_spoof.sendp", lambda pkt, **kw: captured.__setitem__("raw", bytes(pkt)))
        spoofer = make_spoofer()
        spoofer._own_mac = "ee:ee:ee:ee:ee:ee"

        spoofer.send(dst_mac="aa:aa:aa:aa:aa:aa", spoofed_ip="10.0.0.1", real_dst_ip="10.0.0.5")

        parsed = Ether(captured["raw"])
        assert parsed[Ether].dst == "aa:aa:aa:aa:aa:aa"
        assert parsed[ARP].op == 2
        assert parsed[ARP].psrc == "10.0.0.1"
        assert parsed[ARP].pdst == "10.0.0.5"
        assert parsed[ARP].hwdst == "aa:aa:aa:aa:aa:aa"
        assert parsed[ARP].hwsrc == "ee:ee:ee:ee:ee:ee"
        assert parsed[ARP].hwtype == 1  # Ethernet
        assert parsed[ARP].ptype == 0x0800  # IPv4
        assert parsed[ARP].hwlen == 6
        assert parsed[ARP].plen == 4


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


class TestRestore:
    def test_does_nothing_when_neither_mac_resolved(self):
        spoofer = make_spoofer(target_mac=None, gateway_mac=None)
        spoofer.send = Mock()

        spoofer.restore()

        spoofer.send.assert_not_called()

    def test_does_nothing_when_only_one_mac_resolved(self):
        spoofer = make_spoofer(gateway_mac=None)
        spoofer.send = Mock()

        spoofer.restore()

        spoofer.send.assert_not_called()

    def test_sends_corrective_replies_with_real_macs_three_times_each(self):
        spoofer = make_spoofer()
        spoofer.send = Mock()

        spoofer.restore()

        assert spoofer.send.call_count == 6
        calls = Counter(
            (call.kwargs["dst_mac"], call.kwargs["spoofed_ip"], call.kwargs["real_dst_ip"], call.kwargs["src_mac"])
            for call in spoofer.send.call_args_list
        )
        # tells the target the gateway's *real* MAC (not ours)
        assert calls[("aa:aa:aa:aa:aa:aa", "10.0.0.1", "10.0.0.5", "bb:bb:bb:bb:bb:bb")] == 3
        # tells the gateway the target's *real* MAC (not ours)
        assert calls[("bb:bb:bb:bb:bb:bb", "10.0.0.5", "10.0.0.1", "aa:aa:aa:aa:aa:aa")] == 3

    def test_routes_spoof_send_error_to_handle_error(self):
        spoofer = make_spoofer()
        error = SpoofSendError("boom")
        spoofer.send = Mock(side_effect=error)
        spoofer.handle_error = Mock()

        spoofer.restore()

        spoofer.handle_error.assert_called_once_with(error)


class TestHandleError:
    def test_records_error_and_forwards_to_on_error_callback(self):
        on_error = Mock()
        spoofer = make_spoofer(on_error=on_error)
        error = ArpSpoofError("boom")

        spoofer.handle_error(error)

        assert spoofer._error is error
        on_error.assert_called_once_with(error)

    def test_does_not_raise_when_on_error_is_none(self):
        spoofer = make_spoofer(on_error=None)

        spoofer.handle_error(ArpSpoofError("boom"))  # should not raise

        assert isinstance(spoofer._error, ArpSpoofError)

    def test_swallows_exception_raised_by_on_error_callback(self):
        on_error = Mock(side_effect=RuntimeError("callback is broken"))
        spoofer = make_spoofer(on_error=on_error)

        spoofer.handle_error(ArpSpoofError("boom"))  # should not raise/propagate

        on_error.assert_called_once()


class TestLifecycle:
    def test_stop_before_start_does_not_raise(self):
        # macs unresolved -> restore() is a no-op, so this stays a pure lifecycle check
        spoofer = make_spoofer(target_mac=None, gateway_mac=None)

        spoofer.stop()  # _thread is None; should be a no-op, not AttributeError

        assert spoofer._stop_event.is_set()

    def test_start_spawns_a_daemon_thread_running__run(self, monkeypatch):
        started = Mock()
        monkeypatch.setattr(ArpSpoofer, "_run", started)
        spoofer = make_spoofer()

        spoofer.start()
        spoofer._thread.join(timeout=1)

        assert spoofer._thread is not None
        assert spoofer._thread.daemon is True
        started.assert_called_once_with()  # bound as target=self._run, so no explicit self arg

    def test_stop_sets_stop_event_and_joins_thread(self, monkeypatch):
        monkeypatch.setattr(ArpSpoofer, "_run", lambda self: None)
        spoofer = make_spoofer(target_mac=None, gateway_mac=None)
        spoofer.start()

        spoofer.stop()

        assert spoofer._stop_event.is_set()
        assert not spoofer._thread.is_alive()

    def test_stop_always_calls_restore(self, monkeypatch):
        monkeypatch.setattr(ArpSpoofer, "_run", lambda self: None)
        spoofer = make_spoofer()
        spoofer.restore = Mock()
        spoofer.start()

        spoofer.stop()

        spoofer.restore.assert_called_once_with()

    def test_stop_skips_restore_and_logs_if_thread_never_finishes(self, caplog):
        # Simulates join() timing out because _run() is still stuck resolving/
        # poisoning - stop() must not call restore() concurrently with it.
        spoofer = make_spoofer()
        spoofer.restore = Mock()
        fake_thread = Mock()
        fake_thread.is_alive.return_value = True
        spoofer._thread = fake_thread

        with caplog.at_level(logging.ERROR):
            spoofer.stop()

        fake_thread.join.assert_called_once()
        spoofer.restore.assert_not_called()
        assert "did not stop" in caplog.text


class TestRun:
    def test_resolves_missing_macs_then_runs_poison_loop(self, monkeypatch):
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(return_value="ee:ee:ee:ee:ee:ee"))
        spoofer = make_spoofer(target_mac=None, gateway_mac=None)
        spoofer.resolve_mac = Mock(side_effect=["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"])
        spoofer.poison = Mock(side_effect=spoofer._stop_event.set)  # stop after first round

        spoofer._run()

        assert spoofer._own_mac == "ee:ee:ee:ee:ee:ee"
        assert spoofer.target_mac == "aa:aa:aa:aa:aa:aa"
        assert spoofer.gateway_mac == "bb:bb:bb:bb:bb:bb"
        spoofer.poison.assert_called_once_with()

    def test_skips_resolve_mac_when_macs_already_known(self, monkeypatch):
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(return_value="ee:ee:ee:ee:ee:ee"))
        spoofer = make_spoofer()  # both macs already set
        spoofer.resolve_mac = Mock()
        spoofer.poison = Mock(side_effect=spoofer._stop_event.set)

        spoofer._run()

        spoofer.resolve_mac.assert_not_called()

    def test_loops_until_stop_event_is_set(self, monkeypatch):
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(return_value="ee:ee:ee:ee:ee:ee"))
        spoofer = make_spoofer(interval=0)
        calls = []

        def fake_poison():
            calls.append(1)
            if len(calls) == 3:
                spoofer._stop_event.set()

        spoofer.poison = fake_poison

        spoofer._run()

        assert len(calls) == 3

    def test_mac_resolution_error_reaches_handle_error_unwrapped(self, monkeypatch):
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(return_value="ee:ee:ee:ee:ee:ee"))
        spoofer = make_spoofer(target_mac=None, gateway_mac=None)
        error = MacResolutionError("no reply from target")
        spoofer.resolve_mac = Mock(side_effect=error)
        spoofer.handle_error = Mock()

        spoofer._run()

        spoofer.handle_error.assert_called_once_with(error)  # passed through as-is, not rewrapped

    def test_unexpected_exception_is_wrapped_in_arp_spoof_error(self, monkeypatch):
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(side_effect=OSError("no such device")))
        spoofer = make_spoofer()
        spoofer.handle_error = Mock()

        spoofer._run()

        spoofer.handle_error.assert_called_once()
        (wrapped_error,), _ = spoofer.handle_error.call_args
        assert type(wrapped_error) is ArpSpoofError  # generic wrapper, not a MacResolutionError/SpoofSendError
        assert "Unexpected error while ARP-spoofing" in str(wrapped_error)

    def test_full_iteration_sends_two_well_formed_replies_end_to_end(self, monkeypatch):
        # Only the scapy boundary (get_if_hwaddr/sendp) is mocked here - poison()
        # and send() run for real, so this exercises the actual _run -> poison ->
        # send -> sendp chain in one shot rather than trusting each link in isolation.
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(return_value="ee:ee:ee:ee:ee:ee"))
        fake_sendp = Mock()
        monkeypatch.setattr("arp_spoof.sendp", fake_sendp)
        spoofer = make_spoofer()  # macs already known - skips resolve_mac/srp

        sent = []

        def record_and_stop_after_second(pkt, **kwargs):
            sent.append(pkt)
            if len(sent) == 2:
                spoofer._stop_event.set()

        fake_sendp.side_effect = record_and_stop_after_second

        spoofer._run()

        assert len(sent) == 2
        target_pkt, gateway_pkt = sent
        assert target_pkt[Ether].dst == "aa:aa:aa:aa:aa:aa"
        assert target_pkt[ARP].psrc == "10.0.0.1"
        assert target_pkt[ARP].hwsrc == "ee:ee:ee:ee:ee:ee"
        assert gateway_pkt[Ether].dst == "bb:bb:bb:bb:bb:bb"
        assert gateway_pkt[ARP].psrc == "10.0.0.5"
        assert gateway_pkt[ARP].hwsrc == "ee:ee:ee:ee:ee:ee"

    def test_full_run_resolves_macs_and_poisons_end_to_end(self, monkeypatch):
        # Same idea but starting from unknown MACs, so resolve_mac()/srp run for
        # real too - covers the entire chain from a cold start.
        monkeypatch.setattr("arp_spoof.get_if_hwaddr", Mock(return_value="ee:ee:ee:ee:ee:ee"))
        target_reply = Ether(src="aa:aa:aa:aa:aa:aa") / ARP(psrc="10.0.0.5", hwsrc="aa:aa:aa:aa:aa:aa")
        gateway_reply = Ether(src="bb:bb:bb:bb:bb:bb") / ARP(psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb")
        monkeypatch.setattr(
            "arp_spoof.srp",
            Mock(side_effect=[([(Mock(), target_reply)], []), ([(Mock(), gateway_reply)], [])]),
        )
        fake_sendp = Mock()
        monkeypatch.setattr("arp_spoof.sendp", fake_sendp)
        spoofer = make_spoofer(target_mac=None, gateway_mac=None)

        sent = []

        def record_and_stop_after_second(pkt, **kwargs):
            sent.append(pkt)
            if len(sent) == 2:
                spoofer._stop_event.set()

        fake_sendp.side_effect = record_and_stop_after_second

        spoofer._run()

        assert spoofer.target_mac == "aa:aa:aa:aa:aa:aa"
        assert spoofer.gateway_mac == "bb:bb:bb:bb:bb:bb"
        assert len(sent) == 2
