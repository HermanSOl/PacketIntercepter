from __future__ import annotations

import pytest

from ip_forward import IpForwardError, IpForwarder


def make_forwarder(tmp_path, initial: str = "0"):
    path = tmp_path / "ip_forward"
    path.write_text(initial)
    return IpForwarder(path=str(path)), path


class TestEnable:
    def test_turns_forwarding_on_when_it_was_off(self, tmp_path):
        forwarder, path = make_forwarder(tmp_path, initial="0")

        forwarder.enable()

        assert path.read_text() == "1"

    def test_records_original_value_for_restore(self, tmp_path):
        forwarder, _ = make_forwarder(tmp_path, initial="0")

        forwarder.enable()

        assert forwarder._original_value == "0"

    def test_leaves_forwarding_untouched_when_already_on(self, tmp_path):
        forwarder, path = make_forwarder(tmp_path, initial="1")

        forwarder.enable()

        assert path.read_text() == "1"
        assert forwarder._original_value == "1"

    def test_wraps_read_failure_in_ip_forward_error(self, tmp_path):
        forwarder = IpForwarder(path=str(tmp_path / "does_not_exist"))

        with pytest.raises(IpForwardError):
            forwarder.enable()

    def test_wraps_write_failure_in_ip_forward_error(self, tmp_path, monkeypatch):
        forwarder, _ = make_forwarder(tmp_path, initial="0")
        monkeypatch.setattr(forwarder, "_write", lambda value: (_ for _ in ()).throw(IpForwardError("boom")))

        with pytest.raises(IpForwardError):
            forwarder.enable()


class TestRestore:
    def test_restores_original_value_when_it_was_off(self, tmp_path):
        forwarder, path = make_forwarder(tmp_path, initial="0")
        forwarder.enable()

        forwarder.restore()

        assert path.read_text() == "0"

    def test_does_nothing_when_enable_never_ran(self, tmp_path):
        forwarder, path = make_forwarder(tmp_path, initial="0")

        forwarder.restore()

        assert path.read_text() == "0"  # untouched, not written to "0" again via _write

    def test_does_nothing_when_it_was_already_on(self, tmp_path, monkeypatch):
        forwarder, path = make_forwarder(tmp_path, initial="1")
        forwarder.enable()
        fake_write = None

        def spy_write(value):
            nonlocal fake_write
            fake_write = value

        monkeypatch.setattr(forwarder, "_write", spy_write)

        forwarder.restore()

        assert fake_write is None  # _write never called - nothing to undo

    def test_is_idempotent(self, tmp_path):
        forwarder, path = make_forwarder(tmp_path, initial="0")
        forwarder.enable()

        forwarder.restore()
        forwarder.restore()  # should not raise or write again

        assert path.read_text() == "0"
