"""
SSH helper for SEND and Backup when Command Type = SSH (the scan itself is
API-only). Requires paramiko (see requirements.txt); imported lazily so the
API features work without it.

paramiko 4+ dropped the SHA1 key exchanges and the ssh-rsa host key that
RouterOS 6.x offers, so requirements.txt pins paramiko < 4.
"""

from __future__ import annotations

import socket


class SSHUnavailable(RuntimeError):
    pass


class SSHStageError(RuntimeError):
    """SSH failure tagged with the stage it happened at (for the log)."""


def _load_paramiko():
    try:
        import paramiko  # noqa: WPS433 (lazy import by design)
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SSHUnavailable(
            "paramiko is not installed. Run: pip install -r requirements.txt"
        ) from exc
    return paramiko


def _open_ssh(host, username, password, port, timeout):
    """Open a password-authenticated SSH client, naming the failing stage."""
    paramiko = _load_paramiko()
    where = f"{host}:{port}"

    # 1) TCP: tells a wrong/filtered port apart from SSH-level problems
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout as exc:
        raise SSHStageError(
            f"SSH port {where} did not answer (timed out): wrong SSH port, "
            f"ssh service off/restricted in /ip service, or a firewall"
        ) from exc
    except ConnectionRefusedError as exc:
        raise SSHStageError(f"SSH port {where} refused the connection: wrong SSH port?") from exc

    # 2) SSH handshake + login. Same connect options as the version that
    # worked on the real routers (only `timeout`), plus our own socket.
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
            sock=sock,
        )
    except paramiko.AuthenticationException as exc:
        client.close()
        raise SSHStageError(f"SSH login to {where} failed (check username/password)") from exc
    except paramiko.SSHException as exc:
        client.close()
        hint = ""
        if "incompatible" in str(exc).lower():
            hint = (f" (paramiko {paramiko.__version__} can't talk to old RouterOS: "
                    f"pip install \"paramiko<4\")")
        raise SSHStageError(f"SSH handshake with {where} failed: {exc}{hint}") from exc
    except Exception:
        client.close()
        raise
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
        # 3) the command itself
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
        except socket.timeout as exc:
            raise SSHStageError(
                f"SSH connected to {host}:{port} but the command did not finish in {timeout:g}s"
            ) from exc
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
