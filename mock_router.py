#!/usr/bin/env python3
"""
Поддельный MikroTik для проверки без реального железа.

Запускает на твоём же компьютере маленький сервер, который отвечает по
протоколу RouterOS API так же, как настоящий роутер. Тогда основную
программу можно запустить, просканировать 127.0.0.1 и увидеть, как
таблица заполняется — без единого живого микротика.

Запуск:
    python3 mock_router.py
Затем в mikrotik_scanner.py:
    Username: admin   (пароль любой)
    Network:  127.0.0.1
    API-SSL:  8728        (обычный API без шифрования)
    Command Type: любой; для скана порт берётся из поля API-SSL
    New Scan
"""

from __future__ import annotations

import socketserver
from typing import Dict, List

from routeros_api import RouterOSApi  # переиспользуем кодек длины

HOST = "127.0.0.1"
PORT = 8728

# Каждый "виртуальный роутер" — просто набор ответов на команды print.
FAKE_DEVICE = {
    "/system/identity/print": [{"name": "test-router"}],
    "/system/resource/print": [
        {"board-name": "RB4011iGS+", "version": "7.14.3 (stable)", "uptime": "1d2h"}
    ],
    "/system/routerboard/print": [
        {"model": "RB4011iGS+", "serial-number": "HFX0TEST123", "current-firmware": "7.14.3"}
    ],
    "/system/license/print": [{"nlevel": "5", "software-id": "ABCD-1234"}],
    "/ip/address/print": [
        {"address": "10.0.0.2/30", "interface": "ether1"},
        {"address": "127.0.0.1/24", "interface": "bridge1"},
    ],
}


class _ApiCodec:
    """Читает/пишет слова и предложения RouterOS API на стороне сервера."""

    def __init__(self, conn) -> None:
        self.conn = conn

    def _recv(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def read_len(self) -> int:
        c = self._recv(1)[0]
        if (c & 0x80) == 0x00:
            return c
        if (c & 0xC0) == 0x80:
            return ((c & ~0xC0) << 8) + self._recv(1)[0]
        if (c & 0xE0) == 0xC0:
            b = self._recv(2)
            return ((c & ~0xE0) << 16) + (b[0] << 8) + b[1]
        if (c & 0xF0) == 0xE0:
            b = self._recv(3)
            return ((c & ~0xF0) << 24) + (b[0] << 16) + (b[1] << 8) + b[2]
        b = self._recv(4)
        return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]

    def read_word(self) -> str:
        length = self.read_len()
        if length == 0:
            return ""
        return self._recv(length).decode("utf-8", "replace")

    def read_sentence(self) -> List[str]:
        words: List[str] = []
        while True:
            w = self.read_word()
            if w == "":
                return words
            words.append(w)

    def write_word(self, word: str) -> None:
        data = word.encode("utf-8", "replace")
        self.conn.sendall(RouterOSApi.encode_length(len(data)) + data)

    def write_sentence(self, words: List[str]) -> None:
        for w in words:
            self.write_word(w)
        self.write_word("")


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        codec = _ApiCodec(self.request)
        try:
            while True:
                sentence = codec.read_sentence()
                if not sentence:
                    continue
                command = sentence[0]
                if command == "/login":
                    # Принимаем любой логин/пароль — это стенд, не боевой роутер.
                    codec.write_sentence(["!done"])
                    continue
                rows: List[Dict[str, str]] = FAKE_DEVICE.get(command, [])
                for row in rows:
                    words = ["!re"] + [f"={k}={v}" for k, v in row.items()]
                    codec.write_sentence(words)
                codec.write_sentence(["!done"])
        except (ConnectionError, OSError):
            return


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    with ReusableServer((HOST, PORT), Handler) as server:
        print(f"Поддельный MikroTik слушает на {HOST}:{PORT}")
        print("Оставь это окно открытым. Теперь запусти mikrotik_scanner.py и")
        print(f"просканируй Network={HOST}, API-SSL={PORT}. Ctrl+C — остановить.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nОстановлено.")


if __name__ == "__main__":
    main()
