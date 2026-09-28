"""
Shared, GUI-independent logic for the MikroTik scanner:
device polling, de-duplication of multi-homed routers, subnet expansion,
CLI->API command parsing and backup file naming.

Kept free of tkinter so it can be unit tested headlessly.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import ssl
import time
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

from routeros_api import RouterOSApi, RouterOSError

BRIDGE_INTERFACE = "bridge1"


@dataclass
class Device:
    ip: str = ""
    identity: str = ""
    board_name: str = ""
    routeros: str = ""
    license: str = ""
    last_seen: str = ""
    status: str = ""
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
            "Status": self.status,
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
# CLI -> API sentence conversion
# ---------------------------------------------------------------------------
def parse_cli_to_api(line: str) -> List[str]:
    """Convert a RouterOS CLI-style line into an API sentence.

    '/ip address print'              -> ['/ip/address/print']
    '/system identity set name=r1'   -> ['/system/identity/set', '=name=r1']
    '/interface print ?disabled=yes' -> ['/interface/print', '?disabled=yes']
    """
    tokens = shlex.split(line.strip())
    if not tokens:
        return []
    path_parts: List[str] = []
    args: List[str] = []
    for tok in tokens:
        if tok.startswith("?") or tok.startswith("=") or "=" in tok:
            if tok.startswith("?") or tok.startswith("="):
                args.append(tok)
            else:
                args.append("=" + tok)
        else:
            path_parts.append(tok.strip("/"))
    path = "/" + "/".join(path_parts)
    return [path] + args


# ---------------------------------------------------------------------------
# De-duplication of multi-homed routers
# ---------------------------------------------------------------------------
def bridge_ip(addresses: List[Dict[str, str]]) -> Optional[str]:
    """Return the first address bound to bridge1 (prefix stripped)."""
    for addr in addresses:
        if addr.get("interface") == BRIDGE_INTERFACE:
            return addr.get("address", "").split("/")[0]
    return None


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
        preferred = bridge_ip(addresses)
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
            dev.key = rb[0].get("serial-number", "")
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
            {"address": a.get("address", ""), "interface": a.get("interface", "")}
            for a in addrs
        ]
    except RouterOSError:
        pass

    if not (dev.identity or dev.board_name or dev.routeros):
        # every print was refused: don't report an empty row as "OK"
        raise RouterOSError("router returned no data (check user permissions)")


def _is_auth_failure(exc: Exception) -> bool:
    return isinstance(exc, RouterOSError) and "login failed" in str(exc).lower()


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
    last_exc: Exception = RouterOSError("no attempt made")
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
    last_exc: Exception = RouterOSError("no attempt made")
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
        raise RouterOSError("export file did not appear on the router")

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
                raise RouterOSError(
                    "config is %s bytes but this RouterOS returns only %d over the API; "
                    "switch Command Type to SSH (or upgrade to RouterOS 7.13+)"
                    % (size if size is not None else ">4K", got)
                )
    finally:
        try:
            api.talk(["/file/remove", "=numbers=" + info.get(".id", name)])
        except RouterOSError:
            pass  # cleanup is best effort

    if not text.strip():
        raise RouterOSError("export came back empty")
    return text.replace("\r\n", "\n")


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
def sanitize(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned or "unknown"


def backup_filename(ip: str, identity: str, when: Optional[date] = None) -> str:
    when = when or date.today()
    return f"{sanitize(ip)}_{sanitize(identity)}_{when.isoformat()}.rsc"
