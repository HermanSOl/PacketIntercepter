from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from ip_forward import (
    ForwardPolicy,
    ForwardPolicyError,
    IpForwardError,
    IpForwarder,
    RedirectPolicy,
    RedirectPolicyError,
)


def make_forwarder(tmp_path, initial: str = "0"):
    path = tmp_path / "ip_forward"
    path.write_text(initial)
    return IpForwarder(path=str(path)), path


def make_redirect_policy(tmp_path, interface: str = "eth0", all_initial: str = "1", iface_initial: str = "1"):
    path_tmpl = str(tmp_path / "{scope}_send_redirects")
    (tmp_path / "all_send_redirects").write_text(all_initial)
    (tmp_path / f"{interface}_send_redirects").write_text(iface_initial)
    policy = RedirectPolicy(interface, path_tmpl=path_tmpl)
    return policy, policy._paths


def fake_run(policy: str = "DROP"):
    # Mimics `iptables -S FORWARD` / `-P FORWARD <policy>` via subprocess.run,
    # tracking the "live" policy across calls like a real iptables would.
    state = {"policy": policy}

    def run(cmd, **kwargs):
        if cmd[1] == "-S":
            return Mock(stdout=f"-P {cmd[2]} {state['policy']}\n")
        if cmd[1] == "-P":
            state["policy"] = cmd[3]
            return Mock(stdout="")
        raise AssertionError(f"unexpected iptables invocation: {cmd}")

    return run, state


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


class TestForwardPolicyEnable:
    def test_sets_policy_to_accept_when_it_was_drop(self, monkeypatch):
        run, state = fake_run(policy="DROP")
        monkeypatch.setattr(subprocess, "run", run)
        policy = ForwardPolicy()

        policy.enable()

        assert state["policy"] == "ACCEPT"

    def test_records_original_policy_for_restore(self, monkeypatch):
        run, _ = fake_run(policy="DROP")
        monkeypatch.setattr(subprocess, "run", run)
        policy = ForwardPolicy()

        policy.enable()

        assert policy._original_policy == "DROP"

    def test_leaves_policy_untouched_when_already_accept(self, monkeypatch):
        run, state = fake_run(policy="ACCEPT")
        write_calls = []
        real_run = run

        def spy_run(cmd, **kwargs):
            if cmd[1] == "-P":
                write_calls.append(cmd)
            return real_run(cmd, **kwargs)

        monkeypatch.setattr(subprocess, "run", spy_run)
        policy = ForwardPolicy()

        policy.enable()

        assert state["policy"] == "ACCEPT"
        assert write_calls == []  # never wrote - nothing to change

    def test_wraps_read_failure_in_forward_policy_error(self, monkeypatch):
        def raising_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(1, cmd)

        monkeypatch.setattr(subprocess, "run", raising_run)
        policy = ForwardPolicy()

        with pytest.raises(ForwardPolicyError):
            policy.enable()

    def test_wraps_missing_iptables_binary_in_forward_policy_error(self, monkeypatch):
        def missing_run(cmd, **kwargs):
            raise FileNotFoundError("no such file")

        monkeypatch.setattr(subprocess, "run", missing_run)
        policy = ForwardPolicy()

        with pytest.raises(ForwardPolicyError):
            policy.enable()

    def test_raises_when_policy_not_found_in_output(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda cmd, **kwargs: Mock(stdout="-A FORWARD -j DOCKER-USER\n"))
        policy = ForwardPolicy()

        with pytest.raises(ForwardPolicyError):
            policy.enable()


class TestForwardPolicyRestore:
    def test_restores_original_policy_when_it_was_drop(self, monkeypatch):
        run, state = fake_run(policy="DROP")
        monkeypatch.setattr(subprocess, "run", run)
        policy = ForwardPolicy()
        policy.enable()

        policy.restore()

        assert state["policy"] == "DROP"

    def test_does_nothing_when_enable_never_ran(self, monkeypatch):
        write_calls = []

        def spy_run(cmd, **kwargs):
            if cmd[1] == "-P":
                write_calls.append(cmd)
            return Mock(stdout="")

        monkeypatch.setattr(subprocess, "run", spy_run)
        policy = ForwardPolicy()

        policy.restore()

        assert write_calls == []

    def test_does_nothing_when_it_was_already_accept(self, monkeypatch):
        run, state = fake_run(policy="ACCEPT")
        write_calls = []
        real_run = run

        def spy_run(cmd, **kwargs):
            if cmd[1] == "-P":
                write_calls.append(cmd)
            return real_run(cmd, **kwargs)

        monkeypatch.setattr(subprocess, "run", spy_run)
        policy = ForwardPolicy()
        policy.enable()

        policy.restore()

        assert write_calls == []
        assert state["policy"] == "ACCEPT"

    def test_is_idempotent(self, monkeypatch):
        run, state = fake_run(policy="DROP")
        monkeypatch.setattr(subprocess, "run", run)
        policy = ForwardPolicy()
        policy.enable()

        policy.restore()
        policy.restore()  # should not raise or write again

        assert state["policy"] == "DROP"


class TestRedirectPolicyEnable:
    def test_disables_redirects_on_all_and_interface_when_they_were_on(self, tmp_path):
        policy, paths = make_redirect_policy(tmp_path, all_initial="1", iface_initial="1")

        policy.enable()

        assert Path(paths["all"]).read_text() == "0"
        assert Path(paths["eth0"]).read_text() == "0"

    def test_records_original_values_for_restore(self, tmp_path):
        policy, _ = make_redirect_policy(tmp_path, all_initial="1", iface_initial="0")

        policy.enable()

        assert policy._original_values == {"all": "1", "eth0": "0"}

    def test_leaves_redirects_untouched_when_already_off(self, tmp_path):
        policy, paths = make_redirect_policy(tmp_path, all_initial="0", iface_initial="0")

        policy.enable()

        assert Path(paths["all"]).read_text() == "0"
        assert Path(paths["eth0"]).read_text() == "0"

    def test_wraps_read_failure_in_redirect_policy_error(self, tmp_path):
        policy = RedirectPolicy("eth0", path_tmpl=str(tmp_path / "does_not_exist_{scope}"))

        with pytest.raises(RedirectPolicyError):
            policy.enable()

    def test_wraps_write_failure_in_redirect_policy_error(self, tmp_path, monkeypatch):
        policy, _ = make_redirect_policy(tmp_path, all_initial="1", iface_initial="1")
        monkeypatch.setattr(policy, "_write", lambda path, value: (_ for _ in ()).throw(RedirectPolicyError("boom")))

        with pytest.raises(RedirectPolicyError):
            policy.enable()


class TestRedirectPolicyRestore:
    def test_restores_original_values_when_they_were_on(self, tmp_path):
        policy, paths = make_redirect_policy(tmp_path, all_initial="1", iface_initial="1")
        policy.enable()

        policy.restore()

        assert Path(paths["all"]).read_text() == "1"
        assert Path(paths["eth0"]).read_text() == "1"

    def test_does_nothing_when_enable_never_ran(self, tmp_path):
        policy, paths = make_redirect_policy(tmp_path, all_initial="1", iface_initial="1")

        policy.restore()

        assert Path(paths["all"]).read_text() == "1"
        assert Path(paths["eth0"]).read_text() == "1"

    def test_does_nothing_when_it_was_already_off(self, tmp_path, monkeypatch):
        policy, paths = make_redirect_policy(tmp_path, all_initial="0", iface_initial="0")
        policy.enable()
        write_calls = []
        monkeypatch.setattr(policy, "_write", lambda path, value: write_calls.append((path, value)))

        policy.restore()

        assert write_calls == []
        assert Path(paths["all"]).read_text() == "0"
        assert Path(paths["eth0"]).read_text() == "0"

    def test_is_idempotent(self, tmp_path):
        policy, paths = make_redirect_policy(tmp_path, all_initial="1", iface_initial="1")
        policy.enable()

        policy.restore()
        policy.restore()  # should not raise or write again

        assert Path(paths["all"]).read_text() == "1"
        assert Path(paths["eth0"]).read_text() == "1"
