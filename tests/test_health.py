"""Ports, radio and change tracking between two list updates (health.py), and how
they are read over the API (core) and SSH (ssh_client)."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core  # noqa: E402
import health  # noqa: E402
import ssh_client  # noqa: E402
from core import Device  # noqa: E402
from routeros_api import RouterOSError  # noqa: E402


def _port(name="ether1", running=True, rate="1Gbps", fd="true", downs=0, errors=None):
    return {"name": name, "running": running, "rate": rate, "full_duplex": fd,
            "link_downs": downs, "errors": errors or {}}


def test_link_mode_100m_and_1g_full_duplex_are_fine():
    assert health.link_mode_problem("100Mbps", "true") == ""
    assert health.link_mode_problem("1Gbps", "true") == ""
    assert health.link_mode_problem("10Gbps", "true") == ""      # faster than 1G is fine too
    assert health.link_mode_problem("", "") == ""                # not reported: not a problem
    assert health.link_mode_problem("10Mbps", "true") == "10Mbps full-duplex"
    assert health.link_mode_problem("100Mbps", "false") == "100Mbps half-duplex"


def test_port_issues_errors_flaps_and_ports_without_link():
    assert health.port_issues([_port()]) == []
    assert health.port_issues([_port(running=False, rate="10Mbps", fd="false")]) == []  # no link: fine
    issues = health.port_issues([_port(errors={"rx-fcs-error": 12, "tx-collision": 1})])
    assert issues == ["ether1 ошибки rx-fcs-error=12"], issues      # 1 is not above the limit
    old = [_port(downs=4)]
    assert health.port_issues([_port(downs=13)], old) == []
    flapping = health.port_issues([_port(downs=14)], old)
    assert flapping == ["ether1 линк пропадал 10 раз с прошлого обновления"], flapping


def test_error_counters_skip_broadcast_multicast_and_traffic():
    found = health.error_counters({"rx-fcs-error": "5", "rx-broadcast": "900", "rx-multicast": "77",
                                   "rx-bytes": "123456", "tx-drop": "1 204", "rx-align-error": "0",
                                   "rx-pause": "40", "tx-pause": "9", "tx-collision": "1 024"})
    assert found == {"rx-fcs-error": 5, "tx-collision": 1024}, found   # drop / pause are not errors


def test_radio_weak_signal_and_a_drop_since_the_previous_update():
    good = [{"interface": "wlan1", "mac": "AA", "rx": -62, "tx": -64}]
    assert health.radio_issues(good) == []
    weak = [{"interface": "wlan1", "mac": "AA", "rx": -76, "tx": -70}]
    assert health.radio_issues(weak) == ["wlan1: слабый сигнал rx -76"]
    worse = [{"interface": "wlan1", "mac": "AA", "rx": -72, "tx": -66}]
    assert health.radio_issues(worse, good) == [
        "wlan1: сигнал ухудшился с прошлого обновления: rx -62 → -72"]
    assert health.parse_signal("-65dBm@6Mbps") == -65 and health.parse_signal("") is None
    assert health.signal_text(good) == "wlan1 rx -62 / tx -64"


def _full(**kw):
    base = dict(ip="10.0.0.1", identity="R1", board_name="RB951", routeros="6.49", license="4",
                serial="S1", key="S1", extended=True,
                addresses=[{"address": "10.0.0.1/24", "interface": "bridge1", "network": "10.0.0.0"}],
                wireless=[{"name": "wlan1", "ssid": "net", "radio_name": "r1"}])
    base.update(kw)
    return Device(**base)


def test_changes_are_found_and_kept_until_a_backup():
    before = _full()
    after = _full(identity="R1-new", addresses=[{"address": "10.0.0.1/24", "interface": "bridge1", "network": "10.0.0.0"},
                                                {"address": "10.9.9.1/24", "interface": "ether2", "network": "10.9.9.0"}],
                  wireless=[{"name": "wlan1", "ssid": "net2", "radio_name": "r1"}])
    health.analyse(after, before)
    assert after.changes == "имя: R1 → R1-new; wlan1 SSID: net → net2; адреса: +10.9.9.1", after.changes
    assert after.status.startswith("Изменено: имя")
    again = _full(identity="R1-new", addresses=after.addresses, wireless=after.wireless)
    health.analyse(again, after)               # nothing new, but not saved by a backup yet
    assert again.changes == after.changes
    after.changes = ""                          # a backup was made
    third = _full(identity="R1-new", addresses=after.addresses, wireless=after.wireless)
    health.analyse(third, after)
    assert third.changes == "" and third.status == ""


def test_no_comparison_with_rows_that_were_never_read_in_full():
    imported = Device(ip="10.0.0.1", identity="R1")    # CSV / old cache
    fresh = _full(identity="other")
    health.analyse(fresh, imported)
    assert fresh.changes == ""
    health.analyse(fresh, None)                       # a new device
    assert fresh.changes == ""


class _FakeApi:
    def __init__(self, replies):
        self.replies = replies

    def talk(self, words):
        key = " ".join(words)
        if key not in self.replies:
            raise RouterOSError("no such command")
        return self.replies[key]


def test_api_reads_ports_wireless_and_registration_table():
    api = _FakeApi({
        "/interface/ethernet/print =stats=": [
            {"name": "ether1", "running": "true", "rx-fcs-error": "9", "rx-broadcast": "50"},
            {"name": "ether2", "running": "false"}],
        "/interface/print =.proplist=name,link-downs,rx-error,tx-error": [
            {"name": "ether1", "link-downs": "2", "rx-error": "3"}, {"name": "wlan1", "link-downs": "7"}],
        "/interface/ethernet/monitor =numbers=ether1 =once=": [{"rate": "100Mbps", "full-duplex": "false"}],
        "/interface/wireless/print": [{"name": "wlan1", "ssid": "net", "radio-name": "r1",
                                       "disabled": "false", "running": "true"}],
        "/interface/wireless/registration-table/print": [
            {"interface": "wlan1", "mac-address": "AA", "signal-strength": "-78dBm@6Mbps",
             "tx-signal-strength": "-70"}],
    })
    dev = Device(ip="10.0.0.1")
    core._collect_health(api, dev)
    assert dev.extended
    assert dev.ports[0] == {"name": "ether1", "running": True, "rate": "100Mbps", "full_duplex": "false",
                            "link_downs": 2, "errors": {"rx-fcs-error": 9, "rx-error": 3}}, dev.ports[0]
    assert dev.ports[1]["running"] is False and dev.ports[1]["rate"] == ""
    assert dev.wireless[0]["ssid"] == "net" and dev.wireless[0]["link_downs"] == 7 and dev.radio == [{"interface": "wlan1", "mac": "AA", "rx": -78, "tx": -70}]


def test_api_without_wireless_package_is_fine():
    api = _FakeApi({"/interface/ethernet/print": [{"name": "ether1", "running": "false"}]})
    dev = Device(ip="10.0.0.1")
    core._collect_health(api, dev)
    assert dev.extended and dev.wireless == [] and dev.radio == [] and len(dev.ports) == 1


def test_ssh_health_script_is_isolated_and_its_reply_parsed():
    script = ssh_client._health_script()
    assert script.count("[[:parse ") == 8 and script.endswith(':put "__MTSCAN__health=1"')
    assert ssh_client._rsc_string('a "b" $x \\ y') == '"a \\"b\\" \\$x \\\\ y"'
    reply = """__MTSCAN__eth=ether1|true
__MTSCAN__eth=ether2|false
__MTSCAN__ld=ether1|5
__MTSCAN__ld=wlan1|30
__MTSCAN__mon=ether1|10Mbps|true
__MTSCAN__err=ether1|rx-fcs-error|4
__MTSCAN__err=ether1|rx-error|0
__MTSCAN__wlan=wlan1|false|true|tower-1|My|Net
__MTSCAN__reg=wlan1|AA:BB|-80dBm@6Mbps|
__MTSCAN__health=1"""
    dev = Device(ip="10.0.0.1")
    ssh_client.parse_health(reply.splitlines(), dev)
    assert dev.extended
    assert dev.ports[0] == {"name": "ether1", "running": True, "rate": "10Mbps", "full_duplex": "true",
                            "link_downs": 5, "errors": {"rx-fcs-error": 4}}, dev.ports[0]
    assert dev.wireless == [{"name": "wlan1", "disabled": False, "running": True,
                             "radio_name": "tower-1", "ssid": "My|Net", "link_downs": 30}]
    assert dev.radio == [{"interface": "wlan1", "mac": "AA:BB", "rx": -80, "tx": None}]


def test_ssh_reply_without_the_end_marker_is_not_compared():
    dev = Device(ip="10.0.0.1")
    ssh_client.parse_health(["__MTSCAN__eth=ether1|true"], dev)
    assert not dev.extended


def test_old_backups_are_moved_to_old_folder():
    work = tempfile.mkdtemp()
    for name in ("10.0.0.1_R1_2026-01-01.rsc", "10.0.0.1_R1_2026-02-01.rsc", "10.0.0.12_R2_2026-01-01.rsc"):
        with open(os.path.join(work, name), "w") as fh:
            fh.write("x")
    os.makedirs(os.path.join(work, "Old"))
    with open(os.path.join(work, "Old", "10.0.0.1_R1_2026-01-01.rsc"), "w") as fh:
        fh.write("older")
    moved = core.archive_backups(work, "10.0.0.1")
    assert sorted(os.path.basename(p) for p in moved) == ["10.0.0.1_R1_2026-01-01_2.rsc", "10.0.0.1_R1_2026-02-01.rsc"]
    assert sorted(os.listdir(work)) == ["10.0.0.12_R2_2026-01-01.rsc", "Old"]
    assert core.latest_backup_file(work, "10.0.0.1") is None
    assert core.archive_backups(work, "10.0.0.9") == []


def test_wlan_flapping_more_than_10_times_is_weak_radio():
    before = _full(wireless=[{"name": "wlan1", "ssid": "net", "radio_name": "r1", "link_downs": 5}])
    same = _full(wireless=[{"name": "wlan1", "ssid": "net", "radio_name": "r1", "link_downs": 15}])
    health.analyse(same, before)
    assert same.radio_problem == ""                       # 10 is not more than 10
    flapping = _full(wireless=[{"name": "wlan1", "ssid": "net", "radio_name": "r1", "link_downs": 16}])
    health.analyse(flapping, before)
    assert flapping.radio_problem == "wlan1: линк пропадал 11 раз с прошлого обновления"
    assert flapping.status == "Радио: " + flapping.radio_problem


def test_confirmed_problems_leave_the_status_but_changes_stay():
    dev = _full(port_problem="ether1 10Mbps full-duplex", radio_problem="wlan1: слабый сигнал rx -80",
                changes="имя: A → B", confirmed=["radio"])
    assert health.problem_kinds(dev) == ["port", "radio"]
    assert health.open_problem(dev, "port") and not health.open_problem(dev, "radio")
    assert health.status_parts(dev) == ["Изменено: имя: A → B", "Порт: ether1 10Mbps full-duplex"]
    assert health.worst_signal([{"rx": -60, "tx": -71}, {"rx": -65, "tx": None}]) == -71


ADDRS = [
    {"address": "10.20.58.33/28", "interface": "bridge1", "network": "10.20.58.32", "dynamic": False},
    {"address": "10.20.24.132/29", "interface": "ether5", "network": "10.20.24.128", "dynamic": False},
    {"address": "45.87.140.1/32", "interface": "vlan_2", "network": "45.87.140.114", "dynamic": False},
    {"address": "45.87.140.1/32", "interface": "vlan_3", "network": "45.87.140.115", "dynamic": False},
    {"address": "192.168.88.10/24", "interface": "ether1", "network": "192.168.88.0", "dynamic": True},
    {"address": "10.255.0.1/32", "interface": "lo", "network": "10.255.0.1", "dynamic": False},
]


def test_address_kinds_own_client_network_and_dynamic():
    entries = {(e["ip"], e["kind"]) for e in core.address_entries(ADDRS)}
    assert entries == {("10.20.58.33", "own"), ("10.20.24.132", "own"), ("45.87.140.114", "client"),
                       ("45.87.140.115", "client"), ("192.168.88.10", "dynamic"), ("10.255.0.1", "own")}
    assert health.tracked_ips(ADDRS) == {"10.20.58.33", "10.20.24.132", "45.87.140.114", "45.87.140.115",
                                         "10.255.0.1"}


def test_connections_never_go_to_client_addresses():
    dev = Device(ip="10.20.58.33", connect_ip="10.20.24.132", addresses=ADDRS)
    assert core.connect_candidates(dev) == ["10.20.24.132", "10.20.58.33", "10.255.0.1", "192.168.88.10"]
    dev.main_ip = "10.255.0.1"
    assert core.connect_candidates(dev)[0] == "10.255.0.1"
    assert "45.87.140.114" in core.all_ips(dev) and "45.87.140.1" not in core.all_ips(dev)


def test_dynamic_addresses_are_not_changes_but_client_networks_are():
    before = _full(addresses=ADDRS)
    after = _full(addresses=[dict(a, address="192.168.88.77/24") if a["dynamic"] else a for a in ADDRS[:3]]
                  + ADDRS[4:])
    health.analyse(after, before)
    assert after.changes == "адреса: −45.87.140.115", after.changes


def test_unreachable_tells_a_silent_address_from_a_wrong_password():
    from routeros_api import RouterOSAuthError
    assert core.is_unreachable(ConnectionRefusedError()) and core.is_unreachable(TimeoutError())
    assert not core.is_unreachable(RouterOSAuthError("bad")) and not core.is_unreachable(RouterOSError("x"))
    assert core.is_unreachable(ssh_client.SSHStageError("x", unreachable=True))
    assert not core.is_unreachable(ssh_client.SSHStageError("login"))


def test_ping_reads_linux_and_windows_output_in_any_language():
    import subprocess

    class Done:
        def __init__(self, out):
            self.stdout = out
    real = subprocess.run
    try:
        subprocess.run = lambda *a, **k: Done(b"64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.42 ms")
        assert core.ping("10.0.0.1", platform="linux") == 0.42
        subprocess.run = lambda *a, **k: Done("Ответ от 10.0.0.1: число байт=32 время=14мс TTL=64".encode("cp866"))
        assert core.ping("10.0.0.1", platform="win32") == 14
        subprocess.run = lambda *a, **k: Done(b"Reply from 10.0.0.254: Destination host unreachable.")
        assert core.ping("10.0.0.1", platform="win32") is None
    finally:
        subprocess.run = real
    assert core.ping_text(None) == "нет ответа" and core.ping_text(0.4) == "<1 мс" and core.ping_text(14) == "14 мс"
    assert core.parse_subnet("10.20.30.0/24") and core.parse_subnet("10.20.30.1") is None
