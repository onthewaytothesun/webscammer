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
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    # -- connection -------------------------------------------------------
    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.create_default_context()
            # RouterOS default certs are self-signed; operators trust their own
            # devices, so verification is relaxed here (same as Winbox/API-SSL).
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
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
                elif w.startswith("=ret="):
                    attrs["ret"] = w[5:]
            if reply_type == "!re":
                replies.append(attrs)
            elif reply_type == "!done":
                if attrs:
                    replies.append(attrs)
                return replies
            elif reply_type == "!trap" or reply_type == "!fatal":
                raise RouterOSError(attrs.get("message", "; ".join(sentence)))

    # -- login ------------------------------------------------------------
    def login(self) -> None:
        # RouterOS 6.43+ accepts plaintext login in a single sentence.
        try:
            self.talk(["/login", "=name=" + self.username, "=password=" + self.password])
            return
        except RouterOSError:
            pass
        # Legacy challenge/response login (pre-6.43).
        self._write_sentence(["/login"])
        challenge_hex = ""
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            for w in sentence:
                if w.startswith("=ret="):
                    challenge_hex = w[5:]
            if sentence[0] == "!done":
                break
            if sentence[0] in ("!trap", "!fatal"):
                raise RouterOSError("login rejected")
        challenge = binascii.unhexlify(challenge_hex)
        md = hashlib.md5()
        md.update(b"\x00")
        md.update(self.password.encode("utf-8"))
        md.update(challenge)
        response = "00" + md.hexdigest()
        self.talk(["/login", "=name=" + self.username, "=response=" + response])
