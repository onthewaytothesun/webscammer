"""
SSH helper for SEND and Backup when Command Type = SSH (the scan itself is
API-only). Requires paramiko (see requirements.txt); imported lazily so the
API features work without it.

paramiko 4+ dropped the SHA1 key exchanges and the ssh-rsa host key that
RouterOS 6.x offers, so requirements.txt pins paramiko < 4.

Connection problems are reported with the stage they happened at, and for a
failed SSH handshake with what the device actually did (see diagnose_ssh), so
the log says where to look.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from typing import Dict, List, Optional


class SSHUnavailable(RuntimeError):
    pass


class SSHStageError(RuntimeError):
    """SSH failure tagged with the stage it happened at (for the log).

    transient: the connection could not be completed but may work on a retry.
    diagnose:  it failed inside the SSH handshake, so probing the device helps.
    """

    def __init__(self, message: str, transient: bool = False, diagnose: bool = False):
        super().__init__(message)
        self.transient = transient
        self.diagnose = diagnose


def _load_paramiko():
    try:
        import paramiko  # noqa: WPS433 (lazy import by design)
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SSHUnavailable(
            "paramiko is not installed. Run: pip install -r requirements.txt"
        ) from exc
    return paramiko


# ------------------------------------------------------------ diagnosis
def parse_kexinit(payload: bytes) -> Optional[Dict[str, List[str]]]:
    """Algorithm lists from an SSH_MSG_KEXINIT payload (starting at the type byte)."""
    if len(payload) < 17 or payload[0] != 20:
        return None
    pos, lists = 17, []
    for _ in range(10):
        if pos + 4 > len(payload):
            return None
        (n,) = struct.unpack(">I", payload[pos:pos + 4])
        pos += 4
        if pos + n > len(payload):
            return None
        lists.append(payload[pos:pos + n].decode("ascii", "replace").split(",") if n else [])
        pos += n
    return {"kex": lists[0], "host key": lists[1], "cipher": lists[2], "MAC": lists[4]}


def _our_algorithms() -> Optional[Dict[str, List[str]]]:
    try:
        transport = _load_paramiko().Transport
        return {
            "kex": list(transport._preferred_kex),
            "host key": list(transport._preferred_keys),
            "cipher": list(transport._preferred_ciphers),
            "MAC": list(transport._preferred_macs),
        }
    except Exception:  # noqa: BLE001 - private attributes / paramiko missing
        return None


def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    data = b""
    while len(data) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        sock.settimeout(remaining)
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def diagnose_ssh(host: str, port: int, timeout: float = 5.0) -> str:
    """Probe what the device does at the SSH level (one extra short connection).

    Tells apart: nothing answers / the device holds the connection and sends no
    banner / it closes at once / it is not SSH / it starts SSH but the two sides
    share no algorithm / everything looks fine (so the device is busy or rejecting).
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return f"TCP connect failed ({exc})"
    deadline = time.monotonic() + timeout
    try:
        banner = b""
        try:
            while b"\n" not in banner and len(banner) < 512:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                sock.settimeout(remaining)
                chunk = sock.recv(256)
                if not chunk:
                    break
                banner += chunk
        except socket.timeout:
            return (f"TCP connects but the device sends no SSH banner within {timeout:g}s: it is "
                    f"overloaded, or a firewall holds the connection (tarpit / connection limit)")
        except OSError as exc:
            return (f"TCP connects but the connection is reset before any SSH banner ({exc}): "
                    f"connection limit or a firewall rule on the device")
        if not banner:
            return ("TCP connects but the device closes the connection at once, without an SSH "
                    "banner: connection limit / firewall rule, an overloaded device, or the port "
                    "is not SSH")
        line = banner.split(b"\n")[0].decode("ascii", "replace").strip()
        if not line.startswith("SSH-"):
            return f"the port answers, but not with SSH: {line[:40]!r}"
        try:
            sock.sendall(b"SSH-2.0-mikrotik-scanner-probe\r\n")
            head = _recv_exact(sock, 5, deadline)
            (length,) = struct.unpack(">I", head[:4])
            if not 2 <= length <= 35000:
                return f"SSH server '{line}' sent an invalid first packet"
            body = _recv_exact(sock, length - 1, deadline)
            algorithms = parse_kexinit(body[:length - 1 - head[4]])
        except (socket.timeout, EOFError, OSError):
            return (f"SSH server '{line}' answers with its banner, but then stops or closes "
                    f"before the key exchange: the device is overloaded or limiting connections")
        if algorithms is None:
            return f"SSH server '{line}' sent an unreadable key exchange message"
        ours = _our_algorithms()
        if ours:
            missing = [
                f"no common {label}: the device offers {', '.join(algorithms[label])}; "
                f"this program offers {', '.join(ours[label])}"
                for label in ("kex", "host key", "cipher", "MAC")
                if not set(algorithms[label]) & set(ours[label])
            ]
            if missing:
                return f"SSH server '{line}' — " + "; ".join(missing)
        return (f"SSH server '{line}' is alive and shares algorithms with this program, so the "
                f"failure is on the device side: it was busy or limiting connections, or it "
                f"refused the session (see the Disconnect reason if shown)")
    finally:
        sock.close()


# ------------------------------------------------------------- connecting
class _Capture(logging.Handler):
    """Collects paramiko's log lines for one connection (it hides the reason a
    device gives when it ends the session: it only logs it)."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.lines: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())

    def disconnect_reason(self) -> str:
        return next((ln for ln in reversed(self.lines) if ln.startswith("Disconnect")), "")


def _open_once(host, username, password, port, timeout):
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

    # 2) SSH handshake + login
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    channel = f"mikrotik_scanner.ssh.{threading.get_ident()}"
    capture = _Capture()
    channel_logger = logging.getLogger(channel)
    channel_logger.setLevel(logging.INFO)
    channel_logger.propagate = False
    channel_logger.addHandler(capture)
    client.set_log_channel(channel)
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=max(timeout, 20),
            allow_agent=False,
            look_for_keys=False,
            sock=sock,
        )
    except paramiko.AuthenticationException as exc:
        client.close()
        if "timeout" in str(exc).lower():   # a busy device answering too slowly
            raise SSHStageError(f"SSH login to {where} timed out", transient=True) from exc
        raise SSHStageError(f"SSH login to {where} failed (check username/password)") from exc
    except (paramiko.SSHException, EOFError, OSError) as exc:
        client.close()
        reason = capture.disconnect_reason()
        detail = str(exc) or type(exc).__name__
        if reason:
            detail += f" — the device ended the session: {reason}"
        hint = ""
        if "incompatible" in str(exc).lower():
            hint = (f" (paramiko {paramiko.__version__} can't talk to old RouterOS: "
                    f"pip install \"paramiko<4\")")
        incompatible = "incompatible" in str(exc).lower()
        raise SSHStageError(
            f"SSH handshake with {where} failed: {detail}{hint}",
            transient=not incompatible, diagnose=True,
        ) from exc
    except Exception:
        client.close()
        raise
    finally:
        channel_logger.removeHandler(capture)
    return client


def _open_ssh(host, username, password, port, timeout, retries: int = 0):
    """Open a password-authenticated SSH client. A handshake that fails in a way
    that may pass on a second try (banner not sent, session dropped, busy device)
    is retried `retries` times. Only the connection is retried, never a command."""
    attempts = max(0, retries) + 1
    error: Optional[SSHStageError] = None
    for attempt in range(attempts):
        try:
            return _open_once(host, username, password, port, timeout)
        except SSHStageError as exc:
            error = exc
            if exc.transient and attempt + 1 < attempts:
                time.sleep(1.5 * (attempt + 1))   # give a busy router a moment
                continue
            break
    assert error is not None
    message = str(error)
    if attempts > 1 and error.transient:
        message += f" (after {attempts} attempts)"
    if error.diagnose:
        message += f" | diagnosis: {diagnose_ssh(host, port)}"
    if message == str(error):
        raise error
    raise SSHStageError(message, transient=error.transient) from error.__cause__


def run_ssh_command(
    host: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
    timeout: float = 12.0,
    retries: int = 0,
) -> str:
    """Open an SSH connection, run `command`, return combined stdout+stderr."""
    client = _open_ssh(host, username, password, port, timeout, retries)
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
    retries: int = 0,
) -> str:
    """Return the router's textual config (an .rsc script) via /export."""
    text = run_ssh_command(host, username, password, "/export", port=port,
                           timeout=timeout, retries=retries)
    return text.replace("\r\n", "\n")
