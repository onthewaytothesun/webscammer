"""SSH helper tests against small fake servers (no real router needed)."""

import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ssh_client  # noqa: E402


def _serve(behaviour):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    count = [0]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            count[0] += 1
            try:
                behaviour(conn, count[0])
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], count


def _packet(payload: bytes) -> bytes:
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\0" * pad


def _kexinit(kex, host_key, cipher, mac) -> bytes:
    lists = [kex, host_key, cipher, cipher, mac, mac, ["none"], ["none"], [], []]
    body = b"".join(struct.pack(">I", len(",".join(x))) + ",".join(x).encode() for x in lists)
    return _packet(bytes([20]) + b"\0" * 16 + body + b"\0" + b"\0\0\0\0")


def _need_paramiko():
    try:
        import paramiko  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("paramiko is not installed")
    return paramiko


def test_diagnosis_tells_the_failure_kinds_apart():
    def silent(conn, n):
        time.sleep(2)
        conn.close()

    port, _ = _serve(silent)
    assert "не присылает SSH-приветствие" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=0.5)

    port, _ = _serve(lambda conn, n: conn.close())
    assert "сразу закрывает соединение" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=1)

    port, _ = _serve(lambda conn, n: (conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"), conn.close()))
    assert "не SSH" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=1)

    def banner_only(conn, n):
        conn.sendall(b"SSH-2.0-ROSSSH\r\n")
        time.sleep(0.3)
        conn.close()

    port, _ = _serve(banner_only)
    assert "до обмена ключами" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=1)

    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    free_port = dead.getsockname()[1]
    dead.close()
    assert "TCP-подключение не удалось" in ssh_client.diagnose_ssh("127.0.0.1", free_port, timeout=1)


def test_diagnosis_compares_the_devices_algorithms_with_ours():
    _need_paramiko()

    def serve_kexinit(kex):
        def behaviour(conn, n):
            conn.sendall(b"SSH-2.0-ROSSSH\r\n")
            time.sleep(0.05)
            conn.sendall(_kexinit(kex, ["ssh-rsa"], ["aes128-ctr"], ["hmac-sha1"]))
            time.sleep(0.3)
            conn.close()
        return _serve(behaviour)[0]

    text = ssh_client.diagnose_ssh("127.0.0.1", serve_kexinit(["diffie-hellman-group-from-the-stone-age"]), timeout=2)
    assert "нет общих алгоритмов обмена ключами" in text and "diffie-hellman-group-from-the-stone-age" in text, text

    ours = ssh_client._our_algorithms()
    text = ssh_client.diagnose_ssh("127.0.0.1", serve_kexinit([ours["kex"][0]]), timeout=2)
    if "нет общих" in text:   # the stub also offers fixed host key / cipher / MAC lists
        assert "нет общих алгоритмов обмена ключами" not in text, text
    else:
        assert "имеет общие с программой алгоритмы" in text, text


def test_parse_kexinit_reads_the_four_lists():
    payload = _kexinit(["a", "b"], ["hk"], ["c1", "c2"], ["m"])[5:]
    parsed = ssh_client.parse_kexinit(payload)
    assert parsed == {"kex": ["a", "b"], "host key": ["hk"], "cipher": ["c1", "c2"], "MAC": ["m"]}
    assert ssh_client.parse_kexinit(b"\x05" + b"\0" * 40) is None
    assert ssh_client.parse_kexinit(payload[:30]) is None


def test_device_disconnect_reason_reaches_the_error_message():
    """paramiko says only 'Negotiation failed.'; the device's own reason is in its log."""
    _need_paramiko()

    def disconnect(conn, n):
        conn.sendall(b"SSH-2.0-ROSSSH\r\n")
        conn.settimeout(2)
        try:
            conn.recv(4096)
        except OSError:
            pass
        desc = b"no matching key exchange method found"
        conn.sendall(_packet(bytes([1]) + struct.pack(">I", 3) + struct.pack(">I", len(desc)) + desc
                             + struct.pack(">I", 0)))
        time.sleep(0.3)
        conn.close()

    port, _ = _serve(disconnect)
    try:
        ssh_client.run_ssh_command("127.0.0.1", "a", "b", "/export", port=port, timeout=3)
        raise AssertionError("should have failed")
    except ssh_client.SSHStageError as exc:
        message = str(exc)
    assert "Negotiation failed" in message, message
    assert "Disconnect (code 3): no matching key exchange method found" in message, message
    assert "устройство завершило сессию" in message and "диагностика:" in message, message


def test_a_dropped_handshake_is_retried_but_a_wrong_password_is_not():
    paramiko = _need_paramiko()
    real_sleep = ssh_client.time.sleep
    ssh_client.time.sleep = lambda s: None   # skip the back-off pauses
    host_key = paramiko.RSAKey.generate(2048)

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, user, password):
            return paramiko.AUTH_SUCCESSFUL if password == "pw" else paramiko.AUTH_FAILED

        def get_allowed_auths(self, user):
            return "password"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_exec_request(self, channel, command):
            def reply():
                channel.sendall(b"config for " + command)
                channel.send_exit_status(0)
                channel.close()
            threading.Thread(target=reply, daemon=True).start()
            return True

    def flaky(conn, n):
        if n <= 2:              # the first two connections are dropped before any banner
            conn.close()
            return
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        transport.start_server(server=Server())

    try:
        port, count = _serve(flaky)
        out = ssh_client.run_ssh_command("127.0.0.1", "a", "pw", "/export", port=port, timeout=5, retries=2)
        assert out == "config for /export" and count[0] == 3, (out, count[0])

        port, count = _serve(flaky)
        try:
            ssh_client.run_ssh_command("127.0.0.1", "a", "pw", "/export", port=port, timeout=5, retries=0)
            raise AssertionError("no retries: should have failed")
        except ssh_client.SSHStageError as exc:
            assert "banner" in str(exc) and "диагностика:" in str(exc) and not exc.unreachable, str(exc)

        port, count = _serve(lambda conn, n: flaky(conn, 99))
        try:
            ssh_client.run_ssh_command("127.0.0.1", "a", "WRONG", "/export", port=port, timeout=5, retries=2)
            raise AssertionError("wrong password should fail")
        except ssh_client.SSHStageError as exc:
            assert "проверьте логин и пароль" in str(exc) and "диагностика" not in str(exc), str(exc)
        assert count[0] == 1, f"a rejected login must not be retried ({count[0]} connections)"
    finally:
        ssh_client.time.sleep = real_sleep


def test_a_closed_or_silent_port_is_flagged_as_unreachable():
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    try:
        ssh_client.run_ssh_command("127.0.0.1", "a", "b", "/export", port=port, timeout=2)
        raise AssertionError("should have failed")
    except ssh_client.SSHStageError as exc:
        assert exc.unreachable and "отказал в соединении" in str(exc) and "диагностика" not in str(exc), str(exc)


def test_ssh_inventory_retains_management_address_and_deduplicates_by_serial():
    from unittest.mock import patch
    from core import dedupe_devices
    output = """RouterOS banner
__MTSCAN__identity=Office = Main
__MTSCAN__board_name=RB4011
__MTSCAN__routeros=6.49.18 (stable)
__MTSCAN__serial=ABC123
__MTSCAN__license=5
__MTSCAN__address=10.0.0.1/24|bridge1
__MTSCAN__address=192.168.1.1/24|ether1
"""
    with patch.object(ssh_client, "run_ssh_command", return_value=output) as run:
        dev = ssh_client.scan_host_ssh("192.168.1.1", "admin", "secret", port=2222, timeout=7, retries=2)
    assert dev.identity == "Office = Main" and dev.board_name == "RB4011"
    assert dev.routeros == "6.49.18 (stable)" and dev.license == "5" and dev.key == "ABC123"
    assert dev.status == "OK (SSH:2222)"
    dev = dedupe_devices([dev])[0]
    assert dev.ip == "10.0.0.1" and dev.reach_ip == "192.168.1.1"
    assert run.call_args.kwargs == {"port": 2222, "timeout": 7, "retries": 2}


def test_ssh_inventory_supports_chr_and_rejects_empty_or_non_routeros_output():
    from unittest.mock import patch
    output = "__MTSCAN__routeros=7.16.2\n__MTSCAN__software_id=CHR-ID\n__MTSCAN__level=p1"
    with patch.object(ssh_client, "run_ssh_command", return_value=output):
        dev = ssh_client.scan_host_ssh("10.0.0.1", "admin", "secret")
    assert dev.key == "CHR-ID" and dev.license == "p1"
    for output in ("", "syntax error (line 1 column 3)", "Linux server", "__MTSCAN__serial=ABC"):
        with patch.object(ssh_client, "run_ssh_command", return_value=output):
            try:
                ssh_client.scan_host_ssh("10.0.0.1", "admin", "secret")
            except ssh_client.SSHStageError:
                pass
            else:
                assert False, "must not mark failed inventory as OK"


def test_failed_ssh_inventory_says_what_the_device_answered():
    from unittest.mock import patch
    cases = {
        "expected end of command (line 1 column 4)": "expected end of command",
        "bash: -c: syntax error near unexpected token `('": "syntax error",
        "": "ничего не ответило",
    }
    for reply, expected in cases.items():
        with patch.object(ssh_client, "run_ssh_command", return_value=reply):
            try:
                ssh_client.scan_host_ssh("10.0.0.1", "admin", "secret")
                raise AssertionError("must fail")
            except ssh_client.SSHStageError as exc:
                assert expected in str(exc), str(exc)
                assert not exc.unreachable
    long_reply = "x" * 500 + "\r\nsecond line"
    with patch.object(ssh_client, "run_ssh_command", return_value=long_reply):
        try:
            ssh_client.scan_host_ssh("10.0.0.1", "admin", "secret")
        except ssh_client.SSHStageError as exc:
            assert len(str(exc)) < 400 and "…" in str(exc), len(str(exc))


def test_ssh_inventory_reply_goes_to_the_log_file():
    import logging
    from unittest.mock import patch
    records = []

    class Keep(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger("test-ssh-inventory")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(Keep())
    with patch.object(ssh_client, "run_ssh_command", return_value="__MTSCAN__identity=R1\r\n"):
        ssh_client.scan_host_ssh("10.0.0.1", "admin", "secret", logger=logger)
    assert any("10.0.0.1" in r and "__MTSCAN__identity=R1" in r for r in records), records
