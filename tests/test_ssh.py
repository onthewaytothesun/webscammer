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
    assert "no SSH banner" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=0.5)

    port, _ = _serve(lambda conn, n: conn.close())
    assert "closes the connection at once" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=1)

    port, _ = _serve(lambda conn, n: (conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"), conn.close()))
    assert "not with SSH" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=1)

    def banner_only(conn, n):
        conn.sendall(b"SSH-2.0-ROSSSH\r\n")
        time.sleep(0.3)
        conn.close()

    port, _ = _serve(banner_only)
    assert "before the key exchange" in ssh_client.diagnose_ssh("127.0.0.1", port, timeout=1)

    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    free_port = dead.getsockname()[1]
    dead.close()
    assert "TCP connect failed" in ssh_client.diagnose_ssh("127.0.0.1", free_port, timeout=1)


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
    assert "no common kex" in text and "diffie-hellman-group-from-the-stone-age" in text, text

    ours = ssh_client._our_algorithms()
    text = ssh_client.diagnose_ssh("127.0.0.1", serve_kexinit([ours["kex"][0]]), timeout=2)
    if "no common" in text:   # the stub also offers fixed host key / cipher / MAC lists
        assert "no common kex" not in text, text
    else:
        assert "alive and shares algorithms" in text, text


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
    assert "diagnosis:" in message, message


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
            assert "banner" in str(exc) and "diagnosis:" in str(exc), str(exc)

        port, count = _serve(lambda conn, n: flaky(conn, 99))
        try:
            ssh_client.run_ssh_command("127.0.0.1", "a", "WRONG", "/export", port=port, timeout=5, retries=2)
            raise AssertionError("wrong password should fail")
        except ssh_client.SSHStageError as exc:
            assert "check username/password" in str(exc) and "diagnosis" not in str(exc), str(exc)
        assert count[0] == 1, f"a rejected login must not be retried ({count[0]} connections)"
    finally:
        ssh_client.time.sleep = real_sleep
