"""
SSH helper for SEND and Backup when Command Type = SSH (the scan itself is
API-only). Requires paramiko (see requirements.txt); imported lazily so the
API features work without it.
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
    """Open a password-authenticated SSH client (no agent / key files)."""
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
