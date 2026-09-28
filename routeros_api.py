"""
Minimal, dependency-free MikroTik RouterOS API client.

Implements the binary RouterOS API protocol (plain on TCP 8728, TLS on 8729)
so the scanner can talk to devices using credentials the operator supplies.
Only the standard library is required.

Protocol reference: https://help.mikrotik.com/docs/display/ROS/API
"""

from __future__ import annotations

import binascii
import hashlib
import socket
import ssl
from typing import Dict, Iterable, List, Optional


class RouterOSError(Exception):
    """Raised when the router returns a !trap / !fatal sentence."""


class RouterOSApi:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 8728,
        use_ssl: bool = False,
        timeout: float = 8.0,
        logger=None,
        ciphers: Optional[str] = None,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.logger = logger
        # Optional explicit OpenSSL cipher string. When None a broad list is
        # used; callers can force e.g. a CBC-only list as a fallback.
        self.ciphers = ciphers
        self.sock: Optional[socket.socket] = None

    def _log(self, level: str, msg: str, *args) -> None:
        if self.logger is not None:
            getattr(self.logger, level)(msg, *args)

    # -- connection -------------------------------------------------------
    def connect(self) -> None:
        self._log("debug", "%s:%s connect (ssl=%s)", self.host, self.port, self.use_ssl)
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # RouterOS uses self-signed certs (or none); operators trust their
            # own devices, so verification is relaxed (same as Winbox/API-SSL).
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (ValueError, AttributeError):
                pass
            # When a specific (e.g. CBC) cipher list is forced, cap at TLS 1.2:
            # TLS 1.3 GCM suites cannot be disabled via set_ciphers and would
            # otherwise be re-selected, defeating the point of forcing CBC.
            if self.ciphers:
                try:
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                except (ValueError, AttributeError):
                    pass
            # api-ssl without an imported certificate negotiates ANONYMOUS
            # ciphers (ADH-*). Python rejects those by default, which shows up
            # as SSLV3_ALERT_HANDSHAKE_FAILURE. Allow them and drop SECLEVEL so
            # both cert-based and cert-less routers work. A caller may force a
            # specific cipher list (e.g. CBC-only) via self.ciphers.
            candidates = (
                [self.ciphers] if self.ciphers
                else ["ALL:@SECLEVEL=0", "ADH:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0"]
            )
            for ciphers in candidates:
                try:
                    ctx.set_ciphers(ciphers)
                    break
                except ssl.SSLError:
                    continue
            try:
                raw = ctx.wrap_socket(raw, server_hostname=self.host)
            except ssl.SSLError as exc:
                self._log(
                    "error",
                    "%s:%s TLS handshake failed: %s (openssl=%s)",
                    self.host, self.port, exc, ssl.OPENSSL_VERSION,
                )
                raise
            self._log(
                "debug", "%s:%s TLS %s cipher=%s",
                self.host, self.port, raw.version(), raw.cipher(),
            )
        raw.settimeout(self.timeout)
        self.sock = raw

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self) -> "RouterOSApi":
        self.connect()
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- low level word / length encoding --------------------------------
    @staticmethod
    def encode_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        if length < 0x4000:
            length |= 0x8000
            return bytes([(length >> 8) & 0xFF, length & 0xFF])
        if length < 0x200000:
            length |= 0xC00000
            return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        if length < 0x10000000:
            length |= 0xE0000000
            return bytes(
                [
                    (length >> 24) & 0xFF,
                    (length >> 16) & 0xFF,
                    (length >> 8) & 0xFF,
                    length & 0xFF,
                ]
            )
        return bytes(
            [
                0xF0,
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        )

    def _read_len(self) -> int:
        c = self._read_bytes(1)[0]
        if (c & 0x80) == 0x00:
            return c
        if (c & 0xC0) == 0x80:
            return ((c & ~0xC0) << 8) + self._read_bytes(1)[0]
        if (c & 0xE0) == 0xC0:
            n = (c & ~0xE0) << 16
            b = self._read_bytes(2)
            return n + (b[0] << 8) + b[1]
        if (c & 0xF0) == 0xE0:
            n = (c & ~0xF0) << 24
            b = self._read_bytes(3)
            return n + (b[0] << 16) + (b[1] << 8) + b[2]
        b = self._read_bytes(4)
        return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]

    def _read_bytes(self, n: int) -> bytes:
        assert self.sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise RouterOSError("connection closed by router")
            buf += chunk
        return buf

    def _write_word(self, word: str) -> None:
        assert self.sock is not None
        data = word.encode("utf-8", "replace")
        self.sock.sendall(self.encode_length(len(data)) + data)

    def _read_word(self) -> str:
        length = self._read_len()
        if length == 0:
            return ""
        return self._read_bytes(length).decode("utf-8", "replace")

    def _write_sentence(self, words: Iterable[str]) -> None:
        for w in words:
            self._write_word(w)
        self._write_word("")  # empty word terminates the sentence

    def _read_sentence(self) -> List[str]:
        words: List[str] = []
        while True:
            w = self._read_word()
            if w == "":
                return words
            words.append(w)

    # -- talk -------------------------------------------------------------
    def talk(self, words: List[str]) -> List[Dict[str, str]]:
        """Send one sentence, return list of !re reply rows as dicts.

        Raises RouterOSError on !trap/!fatal.
        """
        self._write_sentence(words)
        replies: List[Dict[str, str]] = []
        trap: Optional[str] = None
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            reply_type = sentence[0]
            attrs: Dict[str, str] = {}
            for w in sentence[1:]:
                if w.startswith("="):
                    key, _, val = w[1:].partition("=")
                    attrs[key] = val
            if reply_type == "!re":
                replies.append(attrs)
            elif reply_type == "!trap":
                # RouterOS always follows !trap with !done. Keep reading up to
                # it, otherwise that !done is taken as the reply to the NEXT
                # command and every later reply is shifted by one.
                if trap is None:
                    trap = attrs.get("message", "; ".join(sentence))
            elif reply_type == "!done":
                if trap is not None:
                    raise RouterOSError(trap)
                if attrs:
                    replies.append(attrs)
                return replies
            elif reply_type == "!fatal":
                # the router closes the connection after !fatal
                raise RouterOSError(attrs.get("message", "; ".join(sentence[1:])) or "fatal")

    # -- login ------------------------------------------------------------
    def login(self) -> None:
        # RouterOS 6.43+ authenticates from a single /login with name+password
        # and replies !done with no =ret=. Pre-6.43 routers instead reply with
        # a challenge in =ret=; sending name+password there does NOT log you in,
        # it just hands back the challenge. Treating that !done as success left
        # the session UNAUTHENTICATED, so the next command was dropped by the
        # router (SSLEOFError right after "login"). So: only treat a !done
        # WITHOUT a challenge as success; otherwise do the MD5 response step.
        modern_ok = True
        try:
            replies = self.talk(
                ["/login", "=name=" + self.username, "=password=" + self.password]
            )
        except RouterOSError as exc:
            # Modern routers reject bad credentials here. Very old ones may
            # reject the name/password form, so ask for a bare challenge; if
            # that is refused too, the credentials are wrong.
            self._log("debug", "%s modern login rejected (%s), trying challenge", self.host, exc)
            modern_ok = False
            try:
                replies = self.talk(["/login"])
            except RouterOSError:
                raise RouterOSError("login failed (check username/password)") from exc

        challenge_hex = ""
        for row in replies:
            if row.get("ret"):
                challenge_hex = row["ret"]

        if not challenge_hex:
            if not modern_ok:
                # the name/password login was refused and no challenge came
                # back, so nothing authenticated us
                raise RouterOSError("login failed (check username/password)")
            self._log("debug", "%s login ok (plaintext)", self.host)
            return  # modern login already authenticated

        # Legacy challenge/response (pre-6.43).
        challenge = binascii.unhexlify(challenge_hex)
        md = hashlib.md5()
        md.update(b"\x00")
        md.update(self.password.encode("utf-8"))
        md.update(challenge)
        response = "00" + md.hexdigest()
        try:
            self.talk(["/login", "=name=" + self.username, "=response=" + response])
            self._log("debug", "%s login ok (legacy challenge)", self.host)
        except RouterOSError:
            raise RouterOSError("login failed (check username/password)")
