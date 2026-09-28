"""Headless tests for the GUI-independent logic."""

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (  # noqa: E402
    Device,
    backup_filename,
    bridge_ip,
    dedupe_devices,
    expand_targets,
    parse_cli_to_api,
    _is_auth_failure,
)
from routeros_api import RouterOSApi, RouterOSError  # noqa: E402


def test_expand_cidr():
    hosts = expand_targets("192.168.88.0/30")
    assert hosts == ["192.168.88.1", "192.168.88.2"]


def test_expand_range_and_single():
    assert expand_targets("10.0.0.1") == ["10.0.0.1"]
    assert expand_targets("10.0.0.10-10.0.0.12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert expand_targets("10.0.0.10-12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_expand_dedups_overlap():
    hosts = expand_targets("10.0.0.1, 10.0.0.1 10.0.0.2")
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_parse_cli_print():
    assert parse_cli_to_api("/ip address print") == ["/ip/address/print"]


def test_parse_cli_with_args():
    assert parse_cli_to_api("/system identity set name=r1") == [
        "/system/identity/set",
        "=name=r1",
    ]


def test_parse_cli_with_query():
    assert parse_cli_to_api("/interface print ?disabled=yes") == [
        "/interface/print",
        "?disabled=yes",
    ]


def test_bridge_ip_picks_first_bridge1():
    addrs = [
        {"address": "10.0.0.1/30", "interface": "ether1"},
        {"address": "192.168.88.1/24", "interface": "bridge1"},
        {"address": "192.168.99.1/24", "interface": "bridge1"},
    ]
    assert bridge_ip(addrs) == "192.168.88.1"


def test_dedupe_keeps_single_bridge_row():
    common_addrs = [
        {"address": "10.0.0.2/30", "interface": "ether1"},
        {"address": "192.168.88.1/24", "interface": "bridge1"},
    ]
    a = Device(ip="10.0.0.2", identity="r1", key="SN123", addresses=common_addrs)
    b = Device(ip="192.168.88.1", identity="r1", key="SN123", addresses=common_addrs)
    out = dedupe_devices([a, b])
    assert len(out) == 1
    assert out[0].ip == "192.168.88.1"  # bridge1 address preferred


def test_dedupe_rewrites_to_bridge_when_scanned_via_backup():
    addrs = [
        {"address": "10.0.0.2/30", "interface": "ether1"},
        {"address": "192.168.88.1/24", "interface": "bridge1"},
    ]
    only_backup = Device(ip="10.0.0.2", identity="r1", key="SN123", addresses=addrs)
    out = dedupe_devices([only_backup])
    assert len(out) == 1
    assert out[0].ip == "192.168.88.1"


def test_dedupe_distinct_routers_kept():
    a = Device(ip="192.168.88.1", key="SN1")
    b = Device(ip="192.168.89.1", key="SN2")
    assert len(dedupe_devices([a, b])) == 2


def test_backup_filename_format():
    name = backup_filename("192.168.88.1", "Main Router", when=date(2026, 9, 28))
    assert name == "192.168.88.1_Main_Router_2026-09-28.rsc"


def test_length_encoding_roundtrip_boundaries():
    for value in (0x00, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000):
        encoded = RouterOSApi.encode_length(value)
        assert isinstance(encoded, bytes) and len(encoded) >= 1


def test_auth_failure_detection():
    # a rejected login is definitive -> caller must not retry or fall back
    assert _is_auth_failure(RouterOSError("login failed (check username/password)")) is True
    # a mid-session drop is NOT an auth failure -> caller should retry
    assert _is_auth_failure(RouterOSError("connection closed by router")) is False
    assert _is_auth_failure(TimeoutError()) is False


class _FakeSock:
    """Feeds a canned byte stream to RouterOSApi and swallows writes."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def sendall(self, _data) -> None:
        pass

    def recv(self, n: int) -> bytes:
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk


def _sentence(*words: str) -> bytes:
    out = b""
    for w in words:
        b = w.encode()
        out += RouterOSApi.encode_length(len(b)) + b
    return out + b"\x00"


def test_trap_consumes_its_done_so_next_reply_is_not_shifted():
    api = RouterOSApi("x", "u", "p")
    api.sock = _FakeSock(
        _sentence("!trap", "=message=no such command")
        + _sentence("!done")
        + _sentence("!re", "=name=R1")
        + _sentence("!done")
    )
    try:
        api.talk(["/system/routerboard/print"])
        raise AssertionError("trap not raised")
    except RouterOSError as exc:
        assert "no such command" in str(exc)
    # the next command must get ITS reply, not the trap's leftover !done
    assert api.talk(["/system/identity/print"]) == [{"name": "R1"}]


def test_length_encoding_known_values():
    assert RouterOSApi.encode_length(0x05) == b"\x05"
    assert RouterOSApi.encode_length(0x80) == b"\x80\x80"
    assert RouterOSApi.encode_length(0x4000) == b"\xc0\x40\x00"


def test_backup_index_takes_newest_file_per_ip():
    import tempfile
    import time
    from core import backup_index
    with tempfile.TemporaryDirectory() as d:
        def make(name, age_days):
            path = os.path.join(d, name)
            open(path, "w").write("x")
            t = time.time() - age_days * 86400
            os.utime(path, (t, t))
        make("10.20.44.209_R1_2026-09-01.rsc", 20)
        make("10.20.44.209_R1_2026-09-20.rsc", 2)
        make("10.20.44.20_Other_2026-09-05.rsc", 10)   # must not match ...209
        make("notes.txt", 1)
        make("bad_R1_2026-09-01.rsc", 1)
        idx = backup_index(d)
        assert set(idx) == {"10.20.44.209", "10.20.44.20"}
        assert idx["10.20.44.209"] > idx["10.20.44.20"]
        assert backup_index(os.path.join(d, "missing")) == {}


def test_device_row_has_last_backup_after_last_seen():
    row = Device(ip="1.1.1.1", last_seen="a", last_backup="b").as_row()
    keys = list(row)
    assert keys.index("Last Backup") == keys.index("Last seen") + 1 and row["Last Backup"] == "b"
