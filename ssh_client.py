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


def run_ssh_command(
    host: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
    timeout: float = 12.0,
) -> str:
    """Open an SSH connection, run `command`, return combined stdout+stderr."""
    paramiko = _load_paramiko()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
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
