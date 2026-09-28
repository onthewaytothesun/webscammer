"""
Thin SSH helper used for command dispatch (Command Type = SSH) and for
pulling text backups (/export -> .rsc), which RouterOS emits reliably on
the SSH shell. Requires paramiko (see requirements.txt); imported lazily so
the API-only features work without it.
"""

from __future__ import annotations


class SSHUnavailable(RuntimeError):
    pass


def _load_paramiko():
    try:
        import paramiko  # noqa: WPS433 (lazy import by design)
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SSHUnavailable(
            "paramiko is not installed. Run: pip install paramiko"
        ) from exc
    return paramiko


def _open_ssh(host, username, password, port, timeout):
    """Open an SSH client, tolerating RouterOS's older key-exchange algos."""
    paramiko = _load_paramiko()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def run_ssh_command(
    host: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
    timeout: float = 12.0,
) -> str:
    """Open an SSH connection, run `command`, return combined stdout+stderr."""
    client = _open_ssh(host, username, password, port, timeout)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return (out + err).strip("\r\n")
    finally:
        client.close()


def ssh_scan_host(host, username, password, port=22, timeout=12.0, logger=None):
    """Inventory one router over SSH (no api-ssl / TLS involved)."""
    from core import SSH_SCAN_SCRIPT, parse_ssh_scan  # lazy to avoid import cycle

    if logger:
        logger.debug("%s: SSH scan on port %s", host, port)
    client = _open_ssh(host, username, password, port, timeout)
    try:
        stdin, stdout, stderr = client.exec_command(SSH_SCAN_SCRIPT, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
    finally:
        client.close()
    dev = parse_ssh_scan(out, host)
    if not (dev.identity or dev.board_name or dev.routeros):
        raise RuntimeError("no RouterOS data over SSH: " + (err.strip() or "empty output")[:160])
    if logger:
        logger.debug("%s: SSH scan ok (%s)", host, dev.identity or dev.board_name)
    return dev


def export_config(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: float = 20.0,
) -> str:
    """Return the router's textual config (an .rsc script) via /export."""
    text = run_ssh_command(host, username, password, "/export", port=port, timeout=timeout)
    return text.replace("\r\n", "\n")
