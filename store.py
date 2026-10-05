"""
One settings file next to the program: mt_config.json.

Sections: "settings" (the connection fields, the password only with «Запомнить
настройки»), "commands" (the 10 command drafts), "ui" (column widths / order),
"networks" (subnets scanned with «Скан»), "devices" (the device list).

Every write replaces the whole file atomically (temporary file + rename), so a
crash mid-write never leaves a broken file. The files of older versions
(settings.json, commands.json, devices.json, ui.json) are read once, moved into
it and deleted.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Optional


class ConfigStore:
    def __init__(self, path: str, legacy: Optional[Dict[str, str]] = None, logger=None) -> None:
        self.path = path
        self.logger = logger
        self.error = ""          # why the file could not be read (shown in the log)
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = {}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                self._data = data if isinstance(data, dict) else {}
            except (OSError, ValueError) as exc:
                self.error = str(exc)
                # keep the unreadable file for the operator instead of overwriting it
                try:
                    os.replace(path, path + ".broken")
                except OSError:
                    pass
        elif legacy:
            self._migrate(legacy)

    def _migrate(self, legacy: Dict[str, str]) -> None:
        moved = []
        for section, old in legacy.items():
            if not os.path.exists(old):
                continue
            try:
                with open(old, encoding="utf-8") as fh:
                    self._data[section] = json.load(fh)
                moved.append(old)
            except (OSError, ValueError):
                continue   # a broken old file is left where it is
        if moved and self._write():
            for old in moved:
                try:
                    os.remove(old)
                except OSError:
                    pass

    def get(self, section: str, default=None):
        with self._lock:
            return self._data.get(section, default)

    def has(self, section: str) -> bool:
        with self._lock:
            return section in self._data

    def set(self, section: str, value) -> bool:
        with self._lock:
            self._data[section] = value
            return self._write()

    def remove(self, section: str) -> bool:
        with self._lock:
            if section not in self._data:
                return True
            del self._data[section]
            return self._write()

    def _write(self) -> bool:
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
            return True
        except (OSError, TypeError, ValueError) as exc:
            self.error = str(exc)
            if self.logger:
                self.logger.warning("could not write %s: %s", self.path, exc)
            return False
