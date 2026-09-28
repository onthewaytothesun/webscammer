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
        preferred = bridge_ip(chosen.addresses)
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


# Post-handshake errors that mean "the TLS session dropped mid-conversation"
# (seen on some RouterOS devices right after login). These are transient, so
# we retry the SAME transport with a fresh connection rather than falling back.
_TRANSIENT_SESSION_ERRORS = (ssl.SSLError, ConnectionResetError, TimeoutError, OSError)


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
        return dev
    except Exception as exc:  # noqa: BLE001
        if logger:
            logger.debug("%s: plain API %s also failed: %r", ip, plain_port, exc)
        return None


# TLS cipher profiles tried in order. Some RouterOS builds drop the api-ssl
# session right after login when a GCM cipher is negotiated; forcing CBC fixes
# it. None = broad default list (GCM allowed).
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
        except ssl.SSLError:
            api.close()
            raise  # TLS-level: let caller try the next cipher profile
        except (TimeoutError, OSError) as exc:
            api.close()
            last_exc = exc
            _backoff(logger, ip, attempt, exc)
            continue
        try:
            api.login()
            dev = Device(ip=ip)
            _collect_fields(api, dev)
            dev.status = f"OK (API-SSL:{api_ssl_port})"
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
# SSH scan (alternative transport that avoids api-ssl TLS entirely)
# ---------------------------------------------------------------------------
# Each line prints one labelled value, so the output needs no table parsing.
# routerboard/license are guarded because CHR/x86 have no routerboard.
SSH_SCAN_SCRIPT = "\n".join([
    ':put ("IDENTITY=" . [:tostr [/system identity get name]])',
    ':put ("BOARD=" . [:tostr [/system resource get board-name]])',
    ':put ("VERSION=" . [:tostr [/system resource get version]])',
    ':do { :put ("SERIAL=" . [:tostr [/system routerboard get serial-number]]) } on-error={}',
    ':do { :put ("MODEL=" . [:tostr [/system routerboard get model]]) } on-error={}',
    ':do { :put ("LICENSE=" . [:tostr [/system license get nlevel]]) } on-error={}',
    ':foreach i in=[/ip address find where interface="bridge1"] '
    'do={ :put ("BRIDGE=" . [:tostr [/ip address get $i address]]) }',
])


def parse_ssh_scan(text: str, ip: str) -> Device:
    """Parse the labelled output of SSH_SCAN_SCRIPT into a Device."""
    dev = Device(ip=ip)
    addrs: List[Dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if key == "IDENTITY":
            dev.identity = val
        elif key == "BOARD":
            dev.board_name = val or dev.board_name
        elif key == "VERSION":
            dev.routeros = val
        elif key == "SERIAL":
            dev.key = val or dev.key
        elif key == "MODEL" and not dev.board_name:
            dev.board_name = val
        elif key == "LICENSE":
            dev.license = val
        elif key == "BRIDGE" and val:
            addrs.append({"address": val, "interface": BRIDGE_INTERFACE})
    dev.addresses = addrs
    dev.status = "OK (SSH)"
    return dev


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
def sanitize(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned or "unknown"


def backup_filename(ip: str, identity: str, when: Optional[date] = None) -> str:
    when = when or date.today()
    return f"{sanitize(ip)}_{sanitize(identity)}_{when.isoformat()}.rsc"
