"""
SSH helper for inventory, SEND and Backup when Command Type = SSH.
Requires paramiko (see requirements.txt); imported lazily so the API features
work without it.

paramiko 4+ dropped the SHA1 key exchanges and the ssh-rsa host key that
RouterOS 6.x offers, so requirements.txt pins paramiko < 4.

Connection problems are reported (in Russian, they are shown in the table and the
log) with the stage they happened at, and for a failed SSH handshake with what
the device actually did (see diagnose_ssh), so the log says where to look.
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

    transient:   the connection could not be completed but may work on a retry.
    diagnose:    it failed inside the SSH handshake, so probing the device helps.
    unreachable: nothing answers on that address:port at all (TCP level).
    """

    def __init__(self, message: str, transient: bool = False, diagnose: bool = False,
                 unreachable: bool = False):
        super().__init__(message)
        self.transient = transient
        self.diagnose = diagnose
        self.unreachable = unreachable


def _load_paramiko():
    try:
        import paramiko  # noqa: WPS433 (lazy import by design)
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SSHUnavailable(
            "не установлена библиотека paramiko. Выполните: pip install -r requirements.txt"
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
        return f"TCP-подключение не удалось ({exc})"
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
            return (f"TCP подключается, но устройство не присылает SSH-приветствие за {timeout:g} с: "
                    f"оно перегружено, либо фаервол держит соединение (tarpit / лимит подключений)")
        except OSError as exc:
            return (f"TCP подключается, но соединение сбрасывается до SSH-приветствия ({exc}): "
                    f"лимит подключений или правило фаервола на устройстве")
        if not banner:
            return ("TCP подключается, но устройство сразу закрывает соединение, не прислав "
                    "SSH-приветствие: лимит подключений / правило фаервола, перегруженное "
                    "устройство или на этом порту не SSH")
        line = banner.split(b"\n")[0].decode("ascii", "replace").strip()
        if not line.startswith("SSH-"):
            return f"порт отвечает, но не SSH: {line[:40]!r}"
        try:
            sock.sendall(b"SSH-2.0-mikrotik-scanner-probe\r\n")
            head = _recv_exact(sock, 5, deadline)
            (length,) = struct.unpack(">I", head[:4])
            if not 2 <= length <= 35000:
                return f"SSH-сервер '{line}' прислал некорректный первый пакет"
            body = _recv_exact(sock, length - 1, deadline)
            algorithms = parse_kexinit(body[:length - 1 - head[4]])
        except (socket.timeout, EOFError, OSError):
            return (f"SSH-сервер '{line}' прислал приветствие, но затем замолчал или закрыл "
                    f"соединение до обмена ключами: устройство перегружено или ограничивает подключения")
        if algorithms is None:
            return f"SSH-сервер '{line}' прислал нечитаемое сообщение обмена ключами"
        ours = _our_algorithms()
        if ours:
            names = {"kex": "обмена ключами", "host key": "ключа хоста",
                     "cipher": "шифрования", "MAC": "проверки целостности (MAC)"}
            missing = [
                f"нет общих алгоритмов {names[label]}: устройство предлагает "
                f"{', '.join(algorithms[label])}; программа — {', '.join(ours[label])}"
                for label in ("kex", "host key", "cipher", "MAC")
                if not set(algorithms[label]) & set(ours[label])
            ]
            if missing:
                return f"SSH-сервер '{line}' — " + "; ".join(missing)
        return (f"SSH-сервер '{line}' жив и имеет общие с программой алгоритмы, значит сбой на "
                f"стороне устройства: оно было занято, ограничивало подключения или отклонило "
                f"сессию (причина — в строке Disconnect, если она есть)")
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
            f"SSH-порт {where} не отвечает (таймаут): неверный порт SSH, служба ssh выключена "
            f"или ограничена в /ip service, либо фаервол", unreachable=True,
        ) from exc
    except ConnectionRefusedError as exc:
        raise SSHStageError(
            f"SSH-порт {where} отказал в соединении: неверный порт SSH?", unreachable=True) from exc

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
            raise SSHStageError(f"вход по SSH на {where}: таймаут", transient=True) from exc
        raise SSHStageError(f"не удалось войти по SSH на {where}: проверьте логин и пароль") from exc
    except (paramiko.SSHException, EOFError, OSError) as exc:
        client.close()
        reason = capture.disconnect_reason()
        detail = str(exc) or type(exc).__name__
        if reason:
            detail += f" — устройство завершило сессию: {reason}"
        hint = ""
        if "incompatible" in str(exc).lower():
            hint = (f" (paramiko {paramiko.__version__} не умеет говорить со старыми RouterOS: "
                    f"pip install \"paramiko<4\")")
        incompatible = "incompatible" in str(exc).lower()
        raise SSHStageError(
            f"SSH-рукопожатие с {where} не удалось: {detail}{hint}",
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
        message += f" (после {attempts} попыток)"
    if error.diagnose:
        message += f" | диагностика: {diagnose_ssh(host, port)}"
    if message == str(error):
        raise error
    raise SSHStageError(message, transient=error.transient,
                        unreachable=error.unreachable) from error.__cause__


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
                f"SSH подключён к {host}:{port}, но команда не выполнилась за {timeout:g} с"
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


# Explicit markers avoid parsing RouterOS's human-oriented print tables, whose
# columns and wrapping vary by terminal width/version. Optional properties may
# be absent on CHR or older RouterOS, so each read is isolated with on-error.
_INVENTORY_FIELDS = (
    ("identity", "/system identity get name"),
    ("board_name", "/system resource get board-name"),
    ("routeros", "/system resource get version"),
    ("serial", "/system routerboard get serial-number"),
    ("model", "/system routerboard get model"),
    ("license", "/system license get nlevel"),
    ("level", "/system license get level"),
    ("software_id", "/system license get software-id"),
)
_INVENTORY_SCRIPT = "; ".join(
    ':do { :put ("__MTSCAN__' + key + '=" . [' + command + ']) } on-error={}'
    for key, command in _INVENTORY_FIELDS
) + '; :do { :foreach id in=[/ip address find] do={ :put ("__MTSCAN__address=" . ' \
    '[/ip address get $id address] . "|" . [/ip address get $id interface]) } } on-error={}'



def _rsc_string(code: str) -> str:
    """A RouterOS string literal holding `code` ($ would be expanded, so it is escaped too)."""
    return '"' + code.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _isolated(code: str) -> str:
    """Run `code` so that even a syntax error in it (a menu missing on this device,
    e.g. no wireless package, or an argument this RouterOS does not know) only
    skips this part: RouterOS checks a whole script before running it."""
    return ":do { [[:parse " + _rsc_string(code) + "]] } on-error={}"


def _health_script() -> str:
    from health import SSH_ERROR_COUNTERS
    counters = ";".join(f'"{c}"' for c in SSH_ERROR_COUNTERS)
    parts = [
        ':foreach i in=[/interface ethernet find] do={:put ("__MTSCAN__eth=" . '
        '[/interface ethernet get $i name] . "|" . [/interface ethernet get $i running])}',
        ':foreach i in=[/interface find where (type="ether" or type="wlan")] do={:do {:put ("__MTSCAN__ld=" . '
        '[/interface get $i name] . "|" . [/interface get $i link-downs])} on-error={}}',
        ':foreach i in=[/interface ethernet find where running] do={:do {'
        ':local m [/interface ethernet monitor $i once as-value]; :put ("__MTSCAN__mon=" . '
        '[/interface ethernet get $i name] . "|" . ($m->"rate") . "|" . ($m->"full-duplex"))} on-error={}}',
        ':foreach s in=[/interface ethernet print stats as-value] do={:foreach c in={' + counters + '} do={'
        ':local v ($s->$c); :if ([:len $v] > 0) do={:put ("__MTSCAN__err=" . ($s->"name") . "|" . $c . "|" . $v)}}}',
        ':foreach i in=[/interface find where type="ether"] do={:foreach c in={"rx-error";"tx-error"} do={'
        ':do {:put ("__MTSCAN__err=" . [/interface get $i name] . "|" . $c . "|" . [/interface get $i $c])} on-error={}}}',
        ':foreach i in=[/ip address find] do={:put ("__MTSCAN__addr2=" . [/ip address get $i address] . "|" . '
        '[/ip address get $i interface] . "|" . [/ip address get $i network] . "|" . '
        '[/ip address get $i dynamic] . "|" . [/ip address get $i disabled])}',
        ':foreach i in=[/interface wireless find] do={:put ("__MTSCAN__wlan=" . [/interface wireless get $i name] . "|" . '
        '[/interface wireless get $i disabled] . "|" . [/interface wireless get $i running] . "|" . '
        '[/interface wireless get $i radio-name] . "|" . [/interface wireless get $i ssid])}',
        ':foreach i in=[/interface wireless registration-table find] do={:local tx ""; '
        ':do {:set tx [/interface wireless registration-table get $i tx-signal-strength]} on-error={}; '
        ':put ("__MTSCAN__reg=" . [/interface wireless registration-table get $i interface] . "|" . '
        '[/interface wireless registration-table get $i mac-address] . "|" . '
        '[/interface wireless registration-table get $i signal-strength] . "|" . $tx)}',
    ]
    return "; ".join(_isolated(code) for code in parts) + '; :put "__MTSCAN__health=1"'


def parse_health(lines: List[str], dev) -> None:
    """Fill dev.ports / wireless / radio from the __MTSCAN__ lines of _health_script."""
    import health
    ports: Dict[str, Dict] = {}
    link_downs: Dict[str, Optional[int]] = {}
    addresses: List[Dict] = []
    done = False

    def port(name: str) -> Dict:
        return ports.setdefault(name, {"name": name, "running": False, "rate": "", "full_duplex": "",
                                       "link_downs": None, "errors": {}})
    for line in lines:
        if not line.startswith("__MTSCAN__"):
            continue
        key, sep, value = line[len("__MTSCAN__"):].partition("=")
        if not sep:
            continue
        fields = value.split("|")
        if key == "eth" and len(fields) >= 2:
            port(fields[0])["running"] = fields[1].strip() == "true"
        elif key == "ld" and len(fields) >= 2:
            link_downs[fields[0]] = health.to_int(fields[1])
        elif key == "mon" and len(fields) >= 3 and fields[0] in ports:
            ports[fields[0]]["rate"], ports[fields[0]]["full_duplex"] = fields[1].strip(), fields[2].strip()
        elif key == "err" and len(fields) >= 3 and fields[0] in ports:
            number = health.to_int(fields[2])
            if number and health.is_error_counter(fields[1]):
                ports[fields[0]]["errors"].setdefault(fields[1], number)
        elif key == "wlan" and len(fields) >= 5:
            dev.wireless.append({"name": fields[0], "disabled": fields[1] == "true",
                                 "running": fields[2] == "true", "radio_name": fields[3],
                                 "ssid": "|".join(fields[4:])})
        elif key == "reg" and len(fields) >= 4:
            dev.radio.append({"interface": fields[0], "mac": fields[1],
                              "rx": health.parse_signal(fields[2]), "tx": health.parse_signal(fields[3])})
        elif key == "addr2" and len(fields) >= 5:
            addresses.append({"address": fields[0], "interface": fields[1], "network": fields[2],
                              "dynamic": fields[3] == "true", "disabled": fields[4] == "true"})
        elif key == "health":
            done = True
    for name, downs in link_downs.items():
        if name in ports:
            ports[name]["link_downs"] = downs
    for wlan in dev.wireless:
        wlan["link_downs"] = link_downs.get(wlan["name"])
    if addresses:   # with network / dynamic, which the plain inventory line lacks
        dev.addresses = addresses
    dev.ports = list(ports.values())
    dev.extended = done


def _snippet(text: str, limit: int = 160) -> str:
    """The router's own reply, shortened to one line, for an error message."""
    line = " | ".join(part.strip() for part in text.splitlines() if part.strip())
    return line if len(line) <= limit else line[:limit - 1] + "…"


def scan_host_ssh(host: str, username: str, password: str, port: int = 22,
                  timeout: float = 10.0, retries: int = 2, logger=None):
    """Read RouterOS inventory in one SSH session without changing the router."""
    from core import Device

    output = run_ssh_command(host, username, password, _INVENTORY_SCRIPT + "; " + _health_script(),
                             port=port, timeout=timeout, retries=retries)
    if logger is not None:
        logger.debug("%s: SSH inventory reply: %r", host, output[:2000])
    fields, addresses = {}, []
    for line in output.splitlines():
        if not line.startswith("__MTSCAN__"):
            continue
        key, sep, value = line[len("__MTSCAN__"):].partition("=")
        if not sep:
            continue
        if key == "address":
            address, sep, interface = value.partition("|")
            if sep:
                addresses.append({"address": address, "interface": interface})
        else:
            fields[key] = value
    dev = Device(
        ip=host, connect_ip=host, identity=fields.get("identity", ""),
        board_name=fields.get("board_name") or fields.get("model", ""),
        routeros=fields.get("routeros", ""),
        key=fields.get("serial") or fields.get("software_id", ""), serial=fields.get("serial", ""),
        license=fields.get("license") or fields.get("level", ""),
        addresses=addresses, status=f"OK (SSH:{port})",
    )
    if not (dev.identity or dev.board_name or dev.routeros):
        # Say what actually came back: a permissions problem, a script error on
        # this RouterOS version and a non-RouterOS host all look different here.
        reply = _snippet(output)
        raise SSHStageError(
            "SSH: не удалось прочитать данные RouterOS — "
            + (f"ответ устройства: «{reply}»" if reply else "устройство ничего не ответило")
            + " (нужны права read у пользователя; если это не RouterOS — устройство пропускается)")
    parse_health(output.splitlines(), dev)
    return dev
