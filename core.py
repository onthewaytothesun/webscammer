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

        dev.status = "OK"
    finally:
        api.close()
    return dev


# Errors that mean "we reached an open port but spoke the wrong transport" —
# worth retrying with the other transport. Timeout / refused mean the port is
# simply not there, so we do NOT waste time retrying those.
def _worth_transport_fallback(exc: Exception) -> bool:
    import ssl as _ssl

    if isinstance(exc, _ssl.SSLError):
        return True
    if isinstance(exc, RouterOSError) and "connection closed" in str(exc).lower():
        return True
    if isinstance(exc, ConnectionResetError):
        return True
    return False


def scan_host(
    ip: str,
    username: str,
    password: str,
    api_ssl_port: int,
    plain_port: int = 8728,
    timeout: float = 8.0,
    logger=None,
) -> Device:
    """Poll one host over the RouterOS API.

    Tries API-SSL (TLS) on api_ssl_port first; if that port is open but the
    transport was wrong (TLS/plain mismatch), retries plain API on plain_port.
    The Status field records which transport succeeded. Raises the last error
    if nothing worked.
    """
    attempts = [(True, api_ssl_port, "API-SSL")]
    if plain_port and plain_port != api_ssl_port:
        attempts.append((False, plain_port, "API"))

    last_exc: Exception = RouterOSError("no attempt made")
    for i, (use_ssl, port, label) in enumerate(attempts):
        try:
            if logger:
                logger.debug("%s: try %s on port %s", ip, label, port)
            dev = poll_device(ip, username, password, port, use_ssl, timeout, logger=logger)
            dev.status = f"OK ({label}:{port})"
            return dev
        except Exception as exc:  # noqa: BLE001 - decide whether to fall back
            last_exc = exc
            if logger:
                logger.debug("%s: %s on port %s failed: %r", ip, label, port, exc)
            more_attempts = i + 1 < len(attempts)
            if not (more_attempts and _worth_transport_fallback(exc)):
                break
    raise last_exc


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
def sanitize(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned or "unknown"


def backup_filename(ip: str, identity: str, when: Optional[date] = None) -> str:
    when = when or date.today()
    return f"{sanitize(ip)}_{sanitize(identity)}_{when.isoformat()}.rsc"
