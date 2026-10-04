"""
Shared, GUI-independent logic for the MikroTik scanner:
device polling, de-duplication of multi-homed routers, subnet expansion,
CLI->API command parsing and backup file naming.

Kept free of tkinter so it can be unit tested headlessly.
"""

from __future__ import annotations

import calendar
import ipaddress
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Dict, List, Optional, Tuple

import health
from routeros_api import RouterOSApi, RouterOSAuthError, RouterOSError

BRIDGE_INTERFACE = "bridge1"


@dataclass
class Device:
    ip: str = ""
    identity: str = ""
    board_name: str = ""
    routeros: str = ""
    license: str = ""
    last_seen: str = ""
    last_backup: str = ""
    status: str = ""
    failed: bool = False  # the last operation on this device failed (row turns red)
    note: str = ""  # the operator's own comment, searchable
    # internal
    key: str = ""  # unique hardware key (serial) for de-duplication
    addresses: List[Dict[str, str]] = field(default_factory=list)
    # How the scan actually reached the router. The table shows the bridge1
    # address (`ip`), which may not be reachable from this PC, so Send/Backup
    # connect through these instead.
    connect_ip: str = ""
    api_port: int = 0
    api_ssl: bool = True
    api_ciphers: Optional[str] = None
    # ports, radio and change tracking (see health.py)
    serial: str = ""
    ports: List[Dict] = field(default_factory=list)      # ethernet: name, running, rate, full_duplex, link_downs, errors
    wireless: List[Dict] = field(default_factory=list)   # name, ssid, radio_name, disabled, running
    radio: List[Dict] = field(default_factory=list)      # registration table: interface, mac, rx, tx (dBm)
    extended: bool = False   # the fields above were read (older caches / CSV rows lack them)
    port_problem: str = ""
    radio_problem: str = ""
    changes: str = ""        # changed since an earlier update and not yet saved by a backup
    favorite: bool = False
    confirmed: List[str] = field(default_factory=list)   # problem kinds accepted with «Подтвердить»
    main_ip: str = ""   # chosen by the operator: shown in the table and tried first
    router_id: str = "" # OSPF router-id set on the device ('' when none / 0.0.0.0)
    ping: str = ""      # ping to the device at the last interaction ("12 мс" / "нет ответа")

    @property
    def reach_ip(self) -> str:
        return self.connect_ip or self.ip

    def as_row(self) -> Dict[str, str]:
        return {
            "IP": self.ip,
            "Identity": self.identity,
            "Board Name": self.board_name,
            "RouterOS": self.routeros,
            "License": self.license,
            "Last seen": self.last_seen,
            "Last Backup": self.last_backup,
            "Status": self.status,
            "Note": self.note,
        }


# ---------------------------------------------------------------------------
# Subnet / target expansion
# ---------------------------------------------------------------------------
def expand_targets(spec: str) -> List[str]:
    """Turn a network spec into a list of host IPs.

    Accepts, comma/space separated:
      - CIDR:            192.168.0.0/24
      - single host:     192.168.0.1
      - dash range:      192.168.0.10-192.168.0.20  or  192.168.0.10-20
    """
    hosts: List[str] = []
    seen = set()

    def add(ip: str) -> None:
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)

    for token in re.split(r"[,\s]+", spec.strip()):
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            left = left.strip()
            right = right.strip()
            if "." not in right:  # 192.168.0.10-20 shorthand
                prefix = left.rsplit(".", 1)[0]
                right = prefix + "." + right
            start = int(ipaddress.IPv4Address(left))
            end = int(ipaddress.IPv4Address(right))
            for n in range(start, end + 1):
                add(str(ipaddress.IPv4Address(n)))
        elif "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            if net.num_addresses <= 2:
                for a in net:
                    add(str(a))
            else:
                for a in net.hosts():
                    add(str(a))
        else:
            add(str(ipaddress.ip_address(token)))
    return hosts


# ---------------------------------------------------------------------------
# Commands for Command Type = API/SSL: sent as they are, no conversion
# ---------------------------------------------------------------------------
def split_api_line(line: str) -> List[str]:
    """One API sentence from one line, exactly as typed: words are split on
    spaces (quotes keep a word with spaces together) and nothing is rewritten.

    '/ip/service/set =numbers=ssh =port=61562' -> ['/ip/service/set', '=numbers=ssh', '=port=61562']
    Raises ValueError with a hint when the line is not written as an API command.
    """
    try:
        words = shlex.split(line.strip())
    except ValueError as exc:
        raise ValueError(f"незакрытая кавычка в строке: {line.strip()}") from exc
    if not words:
        return []
    # API words after the command are attributes (=name=value), queries (?name=value)
    # or API options (.tag=1, .proplist=...); a plain word means a terminal command
    if not words[0].startswith("/") or not all(w[:1] in ("=", "?", ".") for w in words[1:]):
        raise ValueError(
            f"«{line.strip()}» — это не команда в формате API. В режиме API/SSL команда пишется "
            f"так: /ip/service/set =numbers=ssh =port=61562. Обычные команды терминала "
            f"выполняются в режиме SSH.")
    return words


# ---------------------------------------------------------------------------
# De-duplication of multi-homed routers
# ---------------------------------------------------------------------------
def bridge_ip(addresses: List[Dict[str, str]]) -> Optional[str]:
    """Return the first address bound to bridge1 (prefix stripped)."""
    for addr in addresses:
        if addr.get("interface") == BRIDGE_INTERFACE:
            return addr.get("address", "").split("/")[0]
    return None


# ---------------------------------------------------------------------------
# The device's addresses: its own, dynamic ones, and client addresses
# ---------------------------------------------------------------------------
def address_entries(addresses: List[Dict]) -> List[Dict]:
    """Every IP the device is known by, one entry each:

      own      a static address of the router (10.20.58.33/28 -> 10.20.58.33)
      dynamic  an address the router got dynamically (DHCP client etc.)
      client   an address handed to a client: on a static /32 interface address
               the remote end is in «network» (address=45.87.140.1 network=45.87.140.114
               -> 45.87.140.114). The /32 address itself (45.87.140.1) is the same
               on many routers and is not listed. A dynamic /32 address is the
               router's own (kind dynamic, its «address» is used).

    Old caches have no «network» / «dynamic»; their addresses count as own."""
    entries: List[Dict] = []
    seen = set()
    for a in addresses:
        address = a.get("address", "")
        ip, _, prefix = address.partition("/")
        if not ip:
            continue
        network = a.get("network", "")
        if a.get("dynamic"):
            kind = "dynamic"
        elif prefix == "32" and network and network != ip:
            kind, ip = "client", network
        else:
            kind = "own"
        if (ip, kind) in seen:
            continue
        seen.add((ip, kind))
        entries.append({"ip": ip, "kind": kind, "interface": a.get("interface", ""),
                        "address": address, "disabled": bool(a.get("disabled"))})
    return entries


def all_ips(dev: Device) -> List[str]:
    """Every IP to search by: the table IP, the connection IP, own / dynamic and client ones."""
    ips = [dev.ip, dev.connect_ip, dev.main_ip] + [e["ip"] for e in address_entries(dev.addresses)]
    return list(dict.fromkeys(ip for ip in ips if ip))


MGMT_NETWORK = ipaddress.ip_network("10.20.0.0/16")  # dynamic addresses are used only inside it


def connect_candidates(dev: Device) -> List[str]:
    """Addresses to connect to, in order: the chosen main IP, the one the scan reached,
    the table IP, then the other own static addresses, then dynamic ones. Never used:
    client addresses and the static /32 addresses they hang on (that would hit the
    clients), and dynamic addresses outside MGMT_NETWORK (the main IP the operator
    chose is always tried)."""
    entries = address_entries(dev.addresses)
    never = {e["ip"] for e in entries if e["kind"] == "client"} | {
        e["address"].split("/")[0] for e in entries if e["kind"] == "client"} | {
        e["ip"] for e in entries if e["kind"] == "dynamic" and not ip_in_subnet(e["ip"], MGMT_NETWORK)}
    order: List[str] = []
    usable = ([dev.main_ip, dev.connect_ip, dev.ip]
              + [e["ip"] for e in entries if e["kind"] == "own" and not e["disabled"]]
              + [e["ip"] for e in entries if e["kind"] == "dynamic" and not e["disabled"]])
    for ip in usable:
        if ip and ip not in order and (ip not in never or ip == dev.main_ip):
            order.append(ip)
    return order


def router_id_ip(dev: Device) -> Optional[str]:
    """The OSPF router-id when it is one of the device's own addresses."""
    if not dev.router_id:
        return None
    for e in address_entries(dev.addresses):
        if e["ip"] == dev.router_id and e["kind"] != "client":
            return e["ip"]
    return None


def auto_ip(dev: Device) -> Optional[str]:
    """The address shown when the operator has not chosen one: the OSPF router-id
    address, else the bridge1 address."""
    return router_id_ip(dev) or bridge_ip(dev.addresses)


def pick_router_id(instances: List[Dict[str, str]], ids: List[Dict[str, str]]) -> str:
    """OSPF router-id from /routing ospf instance rows (RouterOS 6: an address,
    0.0.0.0 = automatic; RouterOS 7: an address or the name of a /routing id entry)
    and /routing id rows (RouterOS 7: name, id). '' when none is set."""
    by_name = {r.get("name", ""): r.get("id", "") for r in ids}
    for inst in instances:
        if inst.get("disabled") == "true":
            continue
        value = inst.get("router-id", "")
        value = by_name.get(value, value)
        try:
            if value and ipaddress.ip_address(value) != ipaddress.ip_address("0.0.0.0"):
                return value
        except ValueError:
            continue
    return ""


def is_unreachable(exc: BaseException) -> bool:
    """Nothing answered on that address (so another address may work); a wrong
    password or a TLS / protocol problem is not that."""
    unreachable = getattr(exc, "unreachable", None)
    if unreachable is not None:
        return bool(unreachable)
    if isinstance(exc, (RouterOSError, ssl.SSLError)):
        return False
    return isinstance(exc, OSError)


def ip_in_subnet(ip: str, network) -> bool:
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def parse_subnet(text: str):
    """'10.20.30.0/24' -> an ip_network; anything else -> None."""
    if "/" not in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


_PING_WIN = re.compile(rb"[=<](\d+)\S*\s+TTL=", re.I)
_PING_UNIX = re.compile(rb"time[=<]\s*([\d.]+)\s*ms", re.I)


def ping(host: str, timeout: float = 1.0, platform: Optional[str] = None) -> Optional[float]:
    """One ICMP echo through the system ping: milliseconds, or None without a reply."""
    platform = platform or sys.platform
    windows = platform.startswith("win")
    if windows:
        args = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    elif platform == "darwin":
        args = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), host]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    kwargs = {"creationflags": 0x08000000} if windows else {}   # CREATE_NO_WINDOW
    try:
        out = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=timeout + 3, **kwargs).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = _PING_UNIX.search(out) or _PING_WIN.search(out)   # Windows prints «время=1мс TTL=64» in any language
    return float(m.group(1)) if m else None


def ping_text(ms: Optional[float]) -> str:
    if ms is None:
        return "нет ответа"
    return "<1 мс" if ms < 1 else f"{ms:.0f} мс"


def dedupe_devices(devices: List[Device]) -> List[Device]:
    """Collapse routers reachable on several IPs into one row.

    Devices sharing a hardware key (serial number) are the same physical
    router seen through different interfaces / backup channels. Keep a single
    row, preferring the address that lives on bridge1 (first in order).
    """
    by_key: Dict[str, List[Device]] = {}
    order: List[str] = []
    result: List[Device] = []

    for dev in devices:
        key = dev.key or dev.ip  # fall back to IP if no serial obtained
        if key not in by_key:
            by_key[key] = []
            order.append(key)
        by_key[key].append(dev)

    for key in order:
        group = by_key[key]
        chosen = group[0]
        # any member that managed to read the address list will do
        addresses = next((m.addresses for m in group if m.addresses), [])
        router_id = next((m.router_id for m in group if m.router_id), "")
        preferred = auto_ip(Device(addresses=addresses, router_id=router_id))
        if preferred:
            # Prefer the group member whose scanned IP is the bridge1 IP.
            for member in group:
                if member.ip == preferred:
                    chosen = member
                    break
            else:
                chosen.ip = preferred
        result.append(chosen)
    return result


# ---------------------------------------------------------------------------
# Device polling over the API
# ---------------------------------------------------------------------------
def poll_device(
    ip: str,
    username: str,
    password: str,
    port: int,
    use_ssl: bool,
    timeout: float = 8.0,
    logger=None,
) -> Device:
    """Connect to one router and collect inventory fields.

    Raises on failure (connection refused, auth error, timeout).
    """
    dev = Device(ip=ip)
    api = RouterOSApi(
        ip, username, password, port=port, use_ssl=use_ssl, timeout=timeout, logger=logger
    )
    api.connect()
    try:
        api.login()
        _collect_fields(api, dev)
        dev.status = "OK"
    finally:
        api.close()
    return dev


def _collect_fields(api: RouterOSApi, dev: Device) -> None:
    """Run the inventory print commands on an already-logged-in session.

    Missing sub-commands (older ROS, restricted user) are tolerated, but a
    dropped connection (SSLEOFError / reset) propagates so the caller can retry.
    """
    try:
        ident = api.talk(["/system/identity/print"])
        if ident:
            dev.identity = ident[0].get("name", "")
    except RouterOSError:
        pass

    try:
        res = api.talk(["/system/resource/print"])
        if res:
            dev.board_name = res[0].get("board-name", "")
            dev.routeros = res[0].get("version", "")
    except RouterOSError:
        pass

    try:
        rb = api.talk(["/system/routerboard/print"])
        if rb:
            dev.key = dev.serial = rb[0].get("serial-number", "")
            if not dev.board_name:
                dev.board_name = rb[0].get("model", "")
    except RouterOSError:
        pass

    try:
        lic = api.talk(["/system/license/print"])
        if lic:
            row = lic[0]
            dev.license = row.get("nlevel") or row.get("level", "")
            if not dev.key:
                dev.key = row.get("software-id", "")
    except RouterOSError:
        pass

    try:
        addrs = api.talk(["/ip/address/print"])
        dev.addresses = [
            {"address": a.get("address", ""), "interface": a.get("interface", ""),
             "network": a.get("network", ""), "dynamic": a.get("dynamic") == "true",
             "disabled": a.get("disabled") == "true"}
            for a in addrs
        ]
    except RouterOSError:
        pass

    if not (dev.identity or dev.board_name or dev.routeros):
        # every print was refused: don't report an empty row as "OK"
        raise RouterOSError("роутер не вернул данных (проверьте права пользователя)")
    _collect_health(api, dev)


def _talk_or_empty(api: RouterOSApi, words: List[str]) -> List[Dict[str, str]]:
    """A print that may not exist here (no wireless package, older RouterOS)."""
    try:
        return api.talk(words)
    except RouterOSError:
        return []


def _collect_health(api: RouterOSApi, dev: Device) -> None:
    """Ethernet ports (link, rate, duplex, errors, link-downs), wireless settings
    and the wireless registration table, for health.analyse()."""
    ports: Dict[str, Dict] = {}
    rows = (_talk_or_empty(api, ["/interface/ethernet/print", "=stats="])
            or _talk_or_empty(api, ["/interface/ethernet/print"]))
    for row in rows:
        name = row.get("name", "")
        if name:
            ports[name] = {"name": name, "running": row.get("running") == "true", "rate": "",
                           "full_duplex": "", "link_downs": None,
                           "errors": health.error_counters(row)}
    link_downs: Dict[str, Optional[int]] = {}
    for row in _talk_or_empty(api, ["/interface/print", "=.proplist=name,link-downs,rx-error,tx-error"]):
        link_downs[row.get("name", "")] = health.to_int(row.get("link-downs"))
        port = ports.get(row.get("name", ""))
        if port is not None:
            port["link_downs"] = health.to_int(row.get("link-downs"))
            for name, value in health.error_counters(row).items():
                port["errors"].setdefault(name, value)
    for port in ports.values():
        if port["running"]:
            mon = _talk_or_empty(api, ["/interface/ethernet/monitor", "=numbers=" + port["name"], "=once="])
            if mon:
                port["rate"] = mon[0].get("rate", "")
                port["full_duplex"] = mon[0].get("full-duplex", "")
    dev.ports = list(ports.values())
    dev.wireless = [
        {"name": r.get("name", ""), "ssid": r.get("ssid", ""), "radio_name": r.get("radio-name", ""),
         "disabled": r.get("disabled") == "true", "running": r.get("running") == "true",
         "link_downs": link_downs.get(r.get("name", ""))}
        for r in _talk_or_empty(api, ["/interface/wireless/print"])
    ]
    dev.radio = [
        {"interface": r.get("interface", ""), "mac": r.get("mac-address", ""),
         "rx": health.parse_signal(r.get("signal-strength", "")),
         "tx": health.parse_signal(r.get("tx-signal-strength", ""))}
        for r in _talk_or_empty(api, ["/interface/wireless/registration-table/print"])
    ]
    dev.router_id = pick_router_id(
        _talk_or_empty(api, ["/routing/ospf/instance/print"]),
        _talk_or_empty(api, ["/routing/id/print"]))
    dev.extended = True


def _is_auth_failure(exc: Exception) -> bool:
    return isinstance(exc, RouterOSAuthError)


def _try_plain_api(
    ip: str, username: str, password: str,
    plain_port: int, api_ssl_port: int, timeout: float, logger=None,
) -> Optional[Device]:
    """Fallback used only when the API-SSL port is genuinely closed/refused."""
    if not plain_port or plain_port == api_ssl_port:
        return None
    try:
        if logger:
            logger.debug("%s: API-SSL port refused, trying plain API on %s", ip, plain_port)
        dev = poll_device(ip, username, password, plain_port, False, timeout, logger=logger)
        dev.status = f"OK (API:{plain_port})"
        dev.connect_ip, dev.api_port, dev.api_ssl = ip, plain_port, False
        return dev
    except Exception as exc:  # noqa: BLE001
        if logger:
            logger.debug("%s: plain API %s also failed: %r", ip, plain_port, exc)
        return None


# TLS cipher profiles tried in order when a profile fails at the TLS level.
# None = broad default list; the CBC list is a compatibility fallback.
_CIPHER_PROFILES = [
    (None, "default"),
    ("ADH-AES256-SHA:ADH-AES128-SHA:AECDH-AES256-SHA:AECDH-AES128-SHA:"
     "AES256-SHA:AES128-SHA:@SECLEVEL=0", "CBC"),
]


class _AuthError(Exception):
    """Wraps a definitive login failure so cipher escalation is skipped."""


def _poll_ssl_with_retries(
    ip, username, password, api_ssl_port, timeout, retries, ciphers, logger,
) -> Device:
    """One cipher profile: connect + login + collect, retrying transient drops.

    Raises _AuthError on bad credentials, ssl.SSLError on TLS-level failure
    (so the caller can try the next cipher profile), or the last transient
    error after exhausting retries.
    """
    last_exc: Exception = RouterOSError("не было ни одной попытки")
    for attempt in range(retries + 1):
        api = RouterOSApi(
            ip, username, password, port=api_ssl_port, use_ssl=True,
            timeout=timeout, logger=logger, ciphers=ciphers,
        )
        started = time.time()
        try:
            api.connect()
        except OSError:
            # Covers TLS handshake errors (caller tries the next cipher
            # profile), refused ports (caller tries plain API) and connect
            # timeouts. A connect timeout almost always means nothing lives at
            # that IP, so retrying it only multiplies scan time on empty
            # addresses; retries are reserved for sessions that drop mid-way.
            api.close()
            raise
        try:
            api.login()
            dev = Device(ip=ip)
            _collect_fields(api, dev)
            dev.status = f"OK (API-SSL:{api_ssl_port})"
            dev.connect_ip, dev.api_port = ip, api_ssl_port
            dev.api_ssl, dev.api_ciphers = True, ciphers
            if logger:
                logger.debug("%s: polled in %.1fs (attempt %d)",
                             ip, time.time() - started, attempt + 1)
            return dev
        except Exception as exc:  # noqa: BLE001
            api.close()
            if _is_auth_failure(exc):
                raise _AuthError(str(exc)) from exc
            last_exc = exc
            _backoff(logger, ip, attempt, exc)  # transient drop -> retry
    raise last_exc


def scan_host(
    ip: str,
    username: str,
    password: str,
    api_ssl_port: int,
    plain_port: int = 8728,
    timeout: float = 10.0,
    retries: int = 2,
    logger=None,
) -> Device:
    """Poll one host over the RouterOS API, robustly.

    Primary transport is API-SSL. For each cipher profile it connects, logs in
    and collects, retrying transient post-login drops `retries` times. If a
    profile keeps failing at the TLS level (handshake or a GCM-triggered
    session drop), the next cipher profile (CBC-only) is tried. Behaviour:
      - api_ssl_port refused (port closed)  -> fall back to plain API once.
      - login rejected (bad credentials)    -> surface immediately, no retry.
    Raises the last error if everything fails.
    """
    last_exc: Exception = RouterOSError("не было ни одной попытки")
    for ciphers, name in _CIPHER_PROFILES:
        try:
            if logger and ciphers is not None:
                logger.debug("%s: retrying with cipher profile '%s'", ip, name)
            return _poll_ssl_with_retries(
                ip, username, password, api_ssl_port, timeout, retries, ciphers, logger,
            )
        except _AuthError as exc:
            raise RouterOSError(str(exc)) from exc  # credentials wrong; stop
        except ssl.SSLError as exc:
            last_exc = exc  # TLS-level failure -> try next cipher profile
            continue
        except ConnectionRefusedError as exc:
            dev = _try_plain_api(ip, username, password, plain_port,
                                 api_ssl_port, timeout, logger)
            if dev is not None:
                return dev
            raise exc  # api-ssl port closed and no plain API either
        except Exception as exc:  # noqa: BLE001 - timeout etc., already retried
            last_exc = exc
            break
    raise last_exc


def _backoff(logger, ip: str, attempt: int, exc: Exception) -> None:
    if logger:
        logger.debug("%s: attempt %d failed (%r), backing off", ip, attempt + 1, exc)
    time.sleep(0.4 * (attempt + 1))


# ---------------------------------------------------------------------------
# Talking to an already-scanned device (Send / Backup)
# ---------------------------------------------------------------------------
def open_device_api(
    dev: Device, username: str, password: str,
    default_port: int, timeout: float = 10.0, logger=None,
) -> RouterOSApi:
    """Connect + log in the same way the scan reached this device.

    Uses the address/port/TLS/cipher recorded by the scan rather than the
    bridge1 address shown in the table (that one may be unreachable).
    Imported rows have no recorded transport, so they get API-SSL on
    default_port.
    """
    api = RouterOSApi(
        dev.reach_ip, username, password,
        port=dev.api_port or default_port,
        use_ssl=dev.api_ssl if dev.api_port else True,
        timeout=timeout, logger=logger, ciphers=dev.api_ciphers,
    )
    api.connect()
    try:
        api.login()
    except Exception:
        api.close()
        raise
    return api


# ---------------------------------------------------------------------------
# Backup over the API: /export file=... then read the file back
# ---------------------------------------------------------------------------
EXPORT_BASENAME = "mtscan-export"
# RouterOS 6 truncates `/file print contents` to this many bytes.
_V6_CONTENTS_LIMIT = 4095
_READ_CHUNK = 32768


class ExportTooLarge(RouterOSError):
    """RouterOS < 7.13 can't hand a config this big over the API."""


def _parse_size(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _find_export_file(api: RouterOSApi) -> Optional[Dict[str, str]]:
    target = EXPORT_BASENAME + ".rsc"
    for row in api.talk(["/file/print", "=.proplist=.id,name,size"]):
        name = row.get("name", "")
        # some boards keep files under flash/
        if name == target or name.endswith("/" + target):
            return row
    return None


def _read_file_chunks(api: RouterOSApi, name: str, size: Optional[int]) -> str:
    """RouterOS 7.13+: /file/read returns the file in chunks of any size."""
    parts: List[str] = []
    offset = 0
    while True:
        rows = api.talk([
            "/file/read", "=file=" + name,
            "=offset=%d" % offset, "=chunk-size=%d" % _READ_CHUNK,
        ])
        data = "".join(r.get("data", "") for r in rows)
        parts.append(data)
        offset += len(data.encode("utf-8"))
        if not data or len(data.encode("utf-8")) < _READ_CHUNK:
            break
        if size is not None and offset >= size:
            break
    return "".join(parts)


def fetch_export(api: RouterOSApi, timeout: float = 20.0, logger=None) -> str:
    """Return the router's /export (.rsc text) using only the API.

    Writes the export to a temporary file on the router, reads it back
    (/file/read on 7.13+, `contents` otherwise) and deletes the file. On
    RouterOS 6 `contents` is capped at ~4 KB, so a larger config raises a
    clear error instead of saving a truncated backup.
    """
    api.talk(["/export", "=file=" + EXPORT_BASENAME])

    # the file can take a moment to appear on slow flash
    info = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = _find_export_file(api)
        if info is not None:
            break
        time.sleep(0.5)
    if info is None:
        raise RouterOSError("файл экспорта не появился на роутере")

    name = info.get("name", EXPORT_BASENAME + ".rsc")
    size = _parse_size(info.get("size", ""))
    try:
        try:
            text = _read_file_chunks(api, name, size)
        except RouterOSError as exc:
            # /file/read does not exist before RouterOS 7.13
            if logger:
                logger.debug("%s: /file/read unavailable (%s), using contents", api.host, exc)
            text = ""
        if text.strip():
            if logger:
                logger.debug("%s: export read via /file/read (%d bytes)", api.host, len(text))
        else:
            rows = api.talk(["/file/print", "?name=" + name, "=.proplist=contents,size"])
            text = rows[0].get("contents", "") if rows else ""
            got = len(text.encode("utf-8"))
            truncated = (size is not None and got < size) or (
                size is None and got >= _V6_CONTENTS_LIMIT
            )
            if truncated:
                raise ExportTooLarge(
                    "конфиг %s байт, а RouterOS старше 7.13 отдаёт по API только %d"
                    % (size if size is not None else ">4K", got)
                )
    finally:
        try:
            api.talk(["/file/remove", "=numbers=" + info.get(".id", name)])
        except RouterOSError:
            pass  # cleanup is best effort

    if not text.strip():
        raise RouterOSError("экспорт пустой")
    return text.replace("\r\n", "\n")


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
def sanitize(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned or "unknown"


_BACKUP_NAME = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})_.*\.rsc$")


def _newest_backups(backup_dir: str) -> Dict[str, Tuple[float, str]]:
    """{ip: (mtime, path)} of the newest IP_Identity_DATE.rsc file per IP."""
    newest: Dict[str, Tuple[float, str]] = {}
    try:
        names = os.listdir(backup_dir)
    except OSError:
        return {}
    for name in names:
        m = _BACKUP_NAME.match(name)
        if not m:
            continue
        path = os.path.join(backup_dir, name)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if mtime > newest.get(m.group(1), (0.0, ""))[0]:
            newest[m.group(1)] = (mtime, path)
    return newest


def backup_index(backup_dir: str) -> Dict[str, str]:
    """Newest backup time per IP, read from the files in the Backups folder.

    Files are named IP_Identity_YYYY-MM-DD.rsc; the time comes from the file's
    modification time. Used for backups made before the app recorded them.
    """
    return {
        ip: datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        for ip, (mtime, _path) in _newest_backups(backup_dir).items()
    }


def latest_backup_file(backup_dir: str, ip: str) -> Optional[str]:
    """Path of the newest backup file for this IP, or None if there is none."""
    found = _newest_backups(backup_dir).get(ip)
    return found[1] if found else None


OLD_BACKUP_DIR = "Old"


def archive_backups(backup_dir: str, ip: str) -> List[str]:
    """Move every backup of this IP from backup_dir into backup_dir/Old (a name
    that is already taken there gets _2, _3…). Returns the new paths."""
    moved: List[str] = []
    try:
        names = sorted(os.listdir(backup_dir))
    except OSError:
        return moved
    old_dir = os.path.join(backup_dir, OLD_BACKUP_DIR)
    for name in names:
        m = _BACKUP_NAME.match(name)
        src = os.path.join(backup_dir, name)
        if not m or m.group(1) != ip or not os.path.isfile(src):
            continue
        os.makedirs(old_dir, exist_ok=True)
        stem, ext = os.path.splitext(name)
        dst, n = os.path.join(old_dir, name), 1
        while os.path.exists(dst):
            n += 1
            dst = os.path.join(old_dir, f"{stem}_{n}{ext}")
        os.replace(src, dst)
        moved.append(dst)
    return moved


def open_with_default_app(path: str, platform: Optional[str] = None) -> None:
    """Open a file with the program the OS associates with it.

    Raises OSError when it can't be started (e.g. no program is associated).
    """
    platform = platform or sys.platform
    if platform.startswith("win"):
        os.startfile(path)  # type: ignore[attr-defined]  # Windows only
    elif platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


# ---------------------------------------------------------------------------
# Progress text
# ---------------------------------------------------------------------------
def format_duration(seconds: float) -> str:
    """45 -> '45 с', 130 -> '2 мин 10 с', 3900 -> '1 ч 05 мин', 100000 -> '1 д 3 ч'."""
    s = int(round(max(0.0, seconds)))
    if s < 60:
        return f"{s} с"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m} мин {s:02d} с" if s else f"{m} мин"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} ч {m:02d} мин" if m else f"{h} ч"
    d, h = divmod(h, 24)
    return f"{d} д {h} ч" if h else f"{d} д"


def estimate_remaining(done: int, total: int, active_elapsed: float,
                       min_done: int = 3, min_elapsed: float = 2.0) -> Optional[float]:
    """Seconds left at the pace so far, or None while it is too early to tell.

    `active_elapsed` must not include time spent paused.
    """
    if total <= 0:
        return None
    if done >= total:
        return 0.0
    if done < min_done or active_elapsed < min_elapsed:
        return None
    return (total - done) * active_elapsed / done


def progress_text(title: str, done: int, total: int, active_elapsed: float, *,
                  ok: int = 0, bad: int = 0, ok_label: str = "", bad_label: str = "",
                  paused: bool = False, finished: bool = False, stopped: bool = False,
                  threads: int = 0) -> str:
    """One line for the progress bar: what runs, how far, how long, how long is left."""
    parts = []
    if finished:
        parts.append(f"{'Остановлено' if stopped else 'Готово'} · {title}: {done} / {total}")
        parts.append(f"за {format_duration(active_elapsed)}")
    else:
        pct = int(done * 100 / total) if total else 100
        head = f"{title}: {done} / {total} ({pct}%)"
        parts.append(("Пауза · " if paused else "") + head)
        if not paused:
            eta = estimate_remaining(done, total, active_elapsed)
            if eta is not None:
                parts.append(f"осталось ≈ {format_duration(eta)}")
        parts.append(f"прошло {format_duration(active_elapsed)}")
    if ok_label:
        parts.append(f"{ok_label}: {ok}")
    if bad_label and bad:
        parts.append(f"{bad_label}: {bad}")
    if threads and not finished:
        parts.append(f"потоков: {threads}")
    return " · ".join(parts)


def looks_like_error(status: str) -> bool:
    """Old caches stored only the status text: recognise the failure ones
    (current Russian texts and the English ones written by earlier versions)."""
    return (status or "").startswith(("Ошибка", "Error", "Command error", "Backup error"))


# ---------------------------------------------------------------------------
# Age of the last backup (row colours and the "older than N months" filter)
# ---------------------------------------------------------------------------
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
AGE_STEPS = (12, 6, 3)  # months, oldest first
AGE_TAGS = {3: "age3", 6: "age6", 12: "age12"}


def parse_time(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime((text or "").strip(), TIME_FORMAT)
    except ValueError:
        return None


def months_before(moment: datetime, months: int) -> datetime:
    """The same day-of-month `months` calendar months earlier (clamped to month end)."""
    year, month = moment.year, moment.month - months
    while month <= 0:
        month += 12
        year -= 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def backup_older_than(last_backup: str, months: int, now: Optional[datetime] = None) -> bool:
    """True when the device has a backup and it is more than `months` months old.
    No backup (or an unreadable date) is not "old": that is what the no-backup filter is for."""
    taken = parse_time(last_backup)
    return taken is not None and taken < months_before(now or datetime.now(), months)


def backup_age_tag(last_backup: str, now: Optional[datetime] = None) -> str:
    """Row colour class: '' (fresh or none), 'age3', 'age6' or 'age12'."""
    now = now or datetime.now()
    for months in AGE_STEPS:
        if backup_older_than(last_backup, months, now):
            return AGE_TAGS[months]
    return ""


def backup_filename(ip: str, identity: str, when: Optional[date] = None) -> str:
    when = when or date.today()
    return f"{sanitize(ip)}_{sanitize(identity)}_{when.isoformat()}.rsc"
