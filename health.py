"""
Port / radio health and change tracking between two list updates.

GUI-independent (unit tested headlessly). A device's ports, wireless settings and
registration table are read during a scan or «Обновить» (core.py over the API,
ssh_client.py over SSH); analyse() compares them with the device as it was
before that update and fills in the problems and changes shown in the table.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

WEAK_SIGNAL = -75        # dBm: a signal below this (rx or tx) is weak
SIGNAL_DROP = 10         # dB worse than at the previous update = degraded
FLAP_LINK_DOWNS = 10     # an ethernet link lost this many times since the previous update = flapping
WLAN_FLAPS = 10          # a wlan link lost MORE than this many times since the previous update = flapping
ERROR_LIMIT = 1          # an error counter above this is a problem

_ERROR_COUNTER = re.compile(
    r"error|fcs|align|fragment|overflow|too-short|too-long|jabber|collision|"
    r"underrun|carrier|deferred")
_NOT_ERROR = re.compile(r"broadcast|multicast|drop|pause")   # drops and pause frames are not errors

# error counters asked for over SSH (the names RouterOS uses in «print stats»)
SSH_ERROR_COUNTERS = (
    "rx-fcs-error", "rx-align-error", "rx-fragment", "rx-overflow", "rx-too-short",
    "rx-too-long", "rx-jabber", "rx-error-events", "rx-code-error", "rx-carrier-error",
    "rx-length-error", "tx-collision", "tx-excessive-collision",
    "tx-multiple-collision", "tx-single-collision", "tx-late-collision", "tx-deferred",
    "tx-excessive-deferred", "tx-underrun", "tx-fcs-error", "tx-too-short", "tx-too-long",
)


def is_error_counter(name: str) -> bool:
    return bool(_ERROR_COUNTER.search(name)) and not _NOT_ERROR.search(name)


def to_int(value) -> Optional[int]:
    """'12', '1 234' (RouterOS 7 groups digits), 12 -> int; anything else -> None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).replace(" ", "").strip()
    return int(text) if re.fullmatch(r"-?\d+", text) else None


def error_counters(stats: Dict[str, str]) -> Dict[str, int]:
    """The non-zero error counters of one port (broadcast / multicast never count)."""
    found = {}
    for name, value in stats.items():
        if is_error_counter(name):
            number = to_int(value)
            if number:
                found[name] = number
    return found


def parse_signal(text) -> Optional[int]:
    """'-65dBm@6Mbps', '-65@HT20-7', '-63' -> -65 / -63; '' -> None."""
    m = re.match(r"\s*(-?\d+)", str(text or ""))
    return int(m.group(1)) if m else None


def _yes(value) -> Optional[bool]:
    text = str(value).strip().lower()
    if text in ("true", "yes"):
        return True
    if text in ("false", "no"):
        return False
    return None


def _rate_mbps(rate: str) -> Optional[float]:
    m = re.match(r"\s*([\d.]+)\s*([MG])", rate or "", re.I)
    if not m:
        return None
    return float(m.group(1)) * (1000 if m.group(2).upper() == "G" else 1)


def link_mode_problem(rate: str, full_duplex) -> str:
    """'' when the link runs 100M or 1G (and faster) full duplex; else what is wrong.
    An unknown rate or duplex (not reported by this port) is not a problem."""
    mbps = _rate_mbps(rate)
    duplex = _yes(full_duplex)
    slow = mbps is not None and mbps != 100 and mbps < 1000
    if slow or duplex is False:
        return f"{rate or '?'} {'half' if duplex is False else 'full'}-duplex"
    return ""


def port_issues(ports: List[Dict], old_ports: Optional[List[Dict]] = None) -> List[str]:
    """Problems of the ethernet ports: a link that is not 100M/1G full duplex,
    error counters above ERROR_LIMIT on a port with link, and flapping (the link
    went down FLAP_LINK_DOWNS+ times since the previous update)."""
    old = {p.get("name"): p for p in old_ports or []}
    issues = []
    for port in ports:
        name = port.get("name", "?")
        found = []
        if port.get("running"):
            mode = link_mode_problem(port.get("rate", ""), port.get("full_duplex", ""))
            if mode:
                found.append(mode)
            errors = {k: v for k, v in (port.get("errors") or {}).items() if v > ERROR_LIMIT}
            if errors:
                worst = sorted(errors.items(), key=lambda kv: -kv[1])[:3]
                found.append("ошибки " + ", ".join(f"{k}={v}" for k, v in worst))
        before = old.get(name)
        now_downs = to_int(port.get("link_downs"))
        then_downs = to_int(before.get("link_downs")) if before else None
        if now_downs is not None and then_downs is not None and now_downs - then_downs >= FLAP_LINK_DOWNS:
            found.append(f"линк пропадал {now_downs - then_downs} раз с прошлого обновления")
        if found:
            issues.append(f"{name} " + ", ".join(found))
    return issues


def _radio_labels(radio: List[Dict]) -> List[str]:
    """'wlan1' for the only client on an interface, 'wlan1 AA:BB:..' when there are several."""
    per_iface: Dict[str, int] = {}
    for entry in radio:
        per_iface[entry.get("interface", "")] = per_iface.get(entry.get("interface", ""), 0) + 1
    return [entry.get("interface", "?") + (f" {entry.get('mac', '')}" if per_iface[entry.get("interface", "")] > 1 else "")
            for entry in radio]


def radio_issues(radio: List[Dict], old_radio: Optional[List[Dict]] = None) -> List[str]:
    """Weak signal (rx or tx below WEAK_SIGNAL) and a signal SIGNAL_DROP+ dB worse
    than at the previous update, per wireless connection (registration-table entry)."""
    old = {(e.get("interface"), e.get("mac")): e for e in old_radio or []}
    issues = []
    for entry, label in zip(radio, _radio_labels(radio)):
        rx, tx = entry.get("rx"), entry.get("tx")
        weak = [f"{side} {value}" for side, value in (("rx", rx), ("tx", tx))
                if value is not None and value < WEAK_SIGNAL]
        if weak:
            issues.append(f"{label}: слабый сигнал " + " / ".join(weak))
        before = old.get((entry.get("interface"), entry.get("mac")))
        if before:
            drops = [f"{side} {then} → {now}" for side, now, then in
                     (("rx", rx, before.get("rx")), ("tx", tx, before.get("tx")))
                     if now is not None and then is not None and now <= then - SIGNAL_DROP]
            if drops:
                issues.append(f"{label}: сигнал ухудшился с прошлого обновления: " + ", ".join(drops))
    return issues


def wlan_flap_issues(wireless: List[Dict], old_wireless: Optional[List[Dict]] = None) -> List[str]:
    """A wlan interface whose link went down more than WLAN_FLAPS times since the previous update."""
    old = {w.get("name"): w for w in old_wireless or []}
    issues = []
    for wlan in wireless:
        now = to_int(wlan.get("link_downs"))
        then = to_int((old.get(wlan.get("name")) or {}).get("link_downs"))
        if now is not None and then is not None and now - then > WLAN_FLAPS:
            issues.append(f"{wlan.get('name')}: линк пропадал {now - then} раз с прошлого обновления")
    return issues


def worst_signal(radio: List[Dict]) -> Optional[int]:
    values = [e[side] for e in radio for side in ("rx", "tx") if e.get(side) is not None]
    return min(values) if values else None


def signal_text(radio: List[Dict]) -> str:
    """For the «Сигнал» column: 'wlan1 rx -68 / tx -70'."""
    parts = []
    for entry, label in zip(radio, _radio_labels(radio)):
        sides = [f"{side} {entry[side]}" for side in ("rx", "tx") if entry.get(side) is not None]
        if sides:
            parts.append(f"{label} " + " / ".join(sides))
    return "; ".join(parts)


_TRACKED = (("serial", "серийный номер"), ("identity", "имя"), ("board_name", "модель"),
            ("routeros", "RouterOS"), ("license", "лицензия"))


def inventory_changes(old, new) -> List[str]:
    """What differs from the previous update: serial, name, model, RouterOS,
    license, wireless SSID / radio-name, IP addresses added or removed.
    Devices read before these fields were collected (old cache, CSV) are not compared."""
    if old is None or not old.extended or not new.extended:
        return []
    changes = []
    for attr, label in _TRACKED:
        before, now = getattr(old, attr) or "", getattr(new, attr) or ""
        if before != now:
            changes.append(f"{label}: {before or '—'} → {now or '—'}")
    old_wlan = {w.get("name"): w for w in old.wireless}
    new_wlan = {w.get("name"): w for w in new.wireless}
    for name in sorted(set(old_wlan) | set(new_wlan)):
        for key, label in (("ssid", "SSID"), ("radio_name", "radio-name")):
            before = (old_wlan.get(name) or {}).get(key, "")
            now = (new_wlan.get(name) or {}).get(key, "")
            if before != now:
                changes.append(f"{name} {label}: {before or '—'} → {now or '—'}")
    # Addresses: own static ones by IP, client ones by the «network» of their /32;
    # dynamic addresses are ignored. A list read before «network» was collected
    # cannot tell client addresses apart, so it is not compared.
    if all("network" in a for a in old.addresses + new.addresses):
        old_addr, new_addr = tracked_ips(old.addresses), tracked_ips(new.addresses)
        moved = [f"+{a}" for a in sorted(new_addr - old_addr)] + [f"−{a}" for a in sorted(old_addr - new_addr)]
        if moved:
            changes.append("адреса: " + ", ".join(moved))
    return changes


def tracked_ips(addresses: List[Dict]) -> set:
    from core import address_entries
    return {e["ip"] for e in address_entries(addresses) if e["kind"] != "dynamic"}


def merge_changes(previous: str, fresh: List[str]) -> str:
    items = [item for item in (previous or "").split("; ") if item]
    for item in fresh:
        if item not in items:
            items.append(item)
    return "; ".join(items)


def analyse(new, base) -> None:
    """Fill new.port_problem / radio_problem / changes and its status, comparing with
    `base` — the same device as it was before this update (None for a new one).

    Changes accumulate until a backup is made (the backup saves them), so a later
    update that finds nothing new keeps the device marked as changed."""
    if not new.extended:
        return
    old_ok = base is not None and base.extended
    new.port_problem = "; ".join(port_issues(new.ports, base.ports if old_ok else None))
    new.radio_problem = "; ".join(radio_issues(new.radio, base.radio if old_ok else None)
                                  + wlan_flap_issues(new.wireless, base.wireless if old_ok else None))
    new.changes = merge_changes(base.changes if base is not None else "", inventory_changes(base, new))
    parts = status_parts(new)
    if parts:
        new.status = " | ".join(parts)


# Problems the operator has accepted with «Подтвердить» (Device.confirmed) stop
# colouring the row and matching the problem filters; changes cannot be confirmed
# (a backup saves them).
PROBLEM_KINDS = ("error", "port", "radio")


def problem_kinds(dev) -> List[str]:
    """Problems the device has now: a failed connection / operation, ports, radio."""
    return [kind for kind, flag in (("error", dev.failed), ("port", dev.port_problem),
                                    ("radio", dev.radio_problem)) if flag]


def open_problem(dev, kind: str) -> bool:
    """The device has this problem and it is not confirmed."""
    return kind in problem_kinds(dev) and kind not in (dev.confirmed or [])


def status_parts(dev) -> List[str]:
    parts = []
    if dev.changes:
        parts.append("Изменено: " + dev.changes)
    if open_problem(dev, "port"):
        parts.append("Порт: " + dev.port_problem)
    if open_problem(dev, "radio"):
        parts.append("Радио: " + dev.radio_problem)
    return parts
