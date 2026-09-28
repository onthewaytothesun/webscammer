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
    parse_ssh_scan,
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


def test_parse_ssh_scan():
    out = (
        "IDENTITY=V_Svobodi_65\n"
        "BOARD=RB4011iGS+\n"
        "VERSION=7.14.3 (stable)\n"
        "SERIAL=HFX0ABC\n"
        "MODEL=RB4011iGS+\n"
        "LICENSE=5\n"
        "BRIDGE=192.168.88.1/24\n"
        "BRIDGE=192.168.99.1/24\n"
    )
    dev = parse_ssh_scan(out, "10.0.0.5")
    assert dev.identity == "V_Svobodi_65"
    assert dev.board_name == "RB4011iGS+"
    assert dev.routeros == "7.14.3 (stable)"
    assert dev.key == "HFX0ABC"
    assert dev.license == "5"
    assert dev.status == "OK (SSH)"
    assert bridge_ip(dev.addresses) == "192.168.88.1"


def test_parse_ssh_scan_falls_back_to_model_when_no_board():
    out = "IDENTITY=CHR1\nBOARD=\nVERSION=7.14\nMODEL=CHR\n"
    dev = parse_ssh_scan(out, "10.0.0.6")
    assert dev.board_name == "CHR"


def test_auth_failure_detection():
    # a rejected login is definitive -> caller must not retry or fall back
    assert _is_auth_failure(RouterOSError("login failed (check username/password)")) is True
    # a mid-session drop is NOT an auth failure -> caller should retry
    assert _is_auth_failure(RouterOSError("connection closed by router")) is False
    assert _is_auth_failure(TimeoutError()) is False


def test_length_encoding_known_values():
    assert RouterOSApi.encode_length(0x05) == b"\x05"
    assert RouterOSApi.encode_length(0x80) == b"\x80\x80"
    assert RouterOSApi.encode_length(0x4000) == b"\xc0\x40\x00"
