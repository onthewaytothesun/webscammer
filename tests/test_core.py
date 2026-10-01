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
    split_api_line,
    _is_auth_failure,
)
from routeros_api import RouterOSApi, RouterOSAuthError, RouterOSError  # noqa: E402


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


def test_api_commands_are_sent_as_typed_without_conversion():
    assert split_api_line("/ip/service/set =numbers=ssh =port=61562") == [
        "/ip/service/set", "=numbers=ssh", "=port=61562"]
    assert split_api_line("/ip/address/print ?interface=bridge1 .proplist=address") == [
        "/ip/address/print", "?interface=bridge1", ".proplist=address"]
    assert split_api_line('/system/identity/set =name="Point 5"') == ["/system/identity/set", "=name=Point 5"]
    assert split_api_line("/system/reboot") == ["/system/reboot"]
    assert split_api_line("   ") == []


def test_terminal_style_commands_are_refused_with_a_hint_not_rewritten():
    for line in ("ip serv set ssh port=61562", "/ip service print", "/ip/service/set numbers=ssh"):
        try:
            split_api_line(line)
            raise AssertionError(f"{line!r} should have been refused")
        except ValueError as exc:
            assert "формате API" in str(exc) and "SSH" in str(exc)
    try:
        split_api_line('/system/identity/set =name="open')
        raise AssertionError("an unclosed quote should be refused")
    except ValueError as exc:
        assert "кавычк" in str(exc)


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
    assert _is_auth_failure(RouterOSAuthError("не удалось войти: проверьте логин и пароль")) is True
    # a mid-session drop is NOT an auth failure -> caller should retry
    assert _is_auth_failure(RouterOSError("роутер закрыл соединение")) is False
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


def test_latest_backup_file_picks_newest_for_that_ip_only():
    import tempfile
    import time
    from core import latest_backup_file
    with tempfile.TemporaryDirectory() as d:
        def make(name, age_days):
            path = os.path.join(d, name)
            open(path, "w").write("x")
            t = time.time() - age_days * 86400
            os.utime(path, (t, t))
            return path
        make("10.20.44.209_Old_Name_2026-08-01.rsc", 30)
        newest = make("10.20.44.209_New_Name_2026-09-20.rsc", 2)   # identity was renamed since
        make("10.20.44.20_Other_2026-09-27.rsc", 1)                # a different device
        make("10.20.44.209_notes.txt", 0)
        assert latest_backup_file(d, "10.20.44.209") == newest
        assert latest_backup_file(d, "10.20.44.99") is None
        assert latest_backup_file(os.path.join(d, "missing"), "10.20.44.209") is None


def test_open_with_default_app_uses_the_platform_opener(monkeypatch=None):
    import core
    calls = []
    real_popen = core.subprocess.Popen
    core.subprocess.Popen = lambda cmd, *a, **k: calls.append(cmd)
    had = hasattr(os, "startfile")
    old_startfile = getattr(os, "startfile", None)
    os.startfile = lambda path: calls.append(("startfile", path))
    try:
        core.open_with_default_app("C:/b/x.rsc", platform="win32")
        core.open_with_default_app("/b/x.rsc", platform="darwin")
        core.open_with_default_app("/b/x.rsc", platform="linux")
    finally:
        core.subprocess.Popen = real_popen
        if had:
            os.startfile = old_startfile
        else:
            del os.startfile
    assert calls == [("startfile", "C:/b/x.rsc"), ["open", "/b/x.rsc"], ["xdg-open", "/b/x.rsc"]]


def test_progress_text_helpers():
    from core import estimate_remaining, format_duration, looks_like_error, progress_text
    assert [format_duration(x) for x in (0, 45, 130, 3900, 100000, 7200)] == \
        ["0 с", "45 с", "2 мин 10 с", "1 ч 05 мин", "1 д 3 ч", "2 ч"]
    assert estimate_remaining(50, 100, 60.0) == 60.0          # half done in a minute -> a minute left
    assert estimate_remaining(2, 100, 60.0) is None           # too early to tell
    assert estimate_remaining(10, 100, 1.0) is None
    assert estimate_remaining(100, 100, 60.0) == 0.0
    assert estimate_remaining(0, 0, 5.0) is None
    running = progress_text("Бэкап", 37, 120, 65, ok=34, bad=3, ok_label="успешно", bad_label="ошибок", threads=10)
    assert running == ("Бэкап: 37 / 120 (30%) · осталось ≈ 2 мин 26 с · прошло 1 мин 05 с · "
                       "успешно: 34 · ошибок: 3 · потоков: 10"), running
    assert progress_text("Бэкап", 1, 120, 1, bad=0, bad_label="ошибок").startswith("Бэкап: 1 / 120 (0%) · прошло 1 с")
    done = progress_text("Бэкап", 120, 120, 100, ok=117, bad=3, ok_label="успешно", bad_label="ошибок", finished=True)
    assert done == "Готово · Бэкап: 120 / 120 · за 1 мин 40 с · успешно: 117 · ошибок: 3", done
    assert progress_text("Сканирование", 45, 2048, 70, finished=True, stopped=True).startswith("Остановлено · Сканирование: 45 / 2048")
    assert progress_text("Команды", 4, 10, 30, paused=True).startswith("Пауза · Команды: 4 / 10 (40%)")
    assert "осталось" not in progress_text("Команды", 4, 10, 30, paused=True)
    assert looks_like_error("Ошибка: TimeoutError") and looks_like_error("Ошибка бэкапа: x") \
        and looks_like_error("Ошибка команды: x")
    assert looks_like_error("Error: TimeoutError") and looks_like_error("Backup error: x") \
        and looks_like_error("Command error: x")      # written by earlier versions
    assert not looks_like_error("OK (API-SSL:8729)") and not looks_like_error("Бэкап: 10.0.0.1_error_x.rsc")


def test_backup_age_colours_and_the_older_than_filter():
    from datetime import datetime
    from core import backup_age_tag, backup_older_than, months_before
    now = datetime(2026, 10, 1, 12, 0, 0)
    cases = {
        "2026-09-29 10:00:00": "",         # fresh
        "2026-07-01 12:00:00": "",         # exactly 3 months: not older yet
        "2026-07-01 11:59:59": "age3",     # just over 3 months -> yellow
        "2026-04-01 11:59:59": "age6",     # over 6 months -> orange
        "2025-10-01 11:59:59": "age12",    # over 12 months -> red
        "2024-01-01 00:00:00": "age12",
        "": "",                            # no backup: handled by the "no backup" filter
        "not a date": "",
    }
    for stamp, tag in cases.items():
        assert backup_age_tag(stamp, now) == tag, (stamp, backup_age_tag(stamp, now))
    assert backup_older_than("2026-04-01 11:59:59", 3, now) and not backup_older_than("2026-04-01 11:59:59", 12, now)
    assert not backup_older_than("", 3, now)
    assert months_before(datetime(2026, 3, 31), 1) == datetime(2026, 2, 28)     # month end is clamped
    assert months_before(datetime(2026, 1, 15), 3) == datetime(2025, 10, 15)    # crosses the year


def test_device_note_is_part_of_the_row_and_the_cache():
    import dataclasses
    row = Device(ip="1.1.1.1", note="Point 5, ask Ivan").as_row()
    assert row["Note"] == "Point 5, ask Ivan" and list(row)[-1] == "Note"
    assert dataclasses.asdict(Device(note="x"))["note"] == "x"
