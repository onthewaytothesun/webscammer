"""
Файловое логирование для наблюдаемости.

Пишет подробный лог каждого запуска в папку logs/ рядом с программой, чтобы
пользователь мог одним файлом прислать полную картину для дебага.
"""

from __future__ import annotations

import logging
import os
import platform
import ssl
import sys
from datetime import datetime


def setup_logging(app_dir: str) -> tuple[logging.Logger, str]:
    logs_dir = os.path.join(app_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    path = os.path.join(logs_dir, f"scanner-{datetime.now():%Y%m%d-%H%M%S}.log")

    logger = logging.getLogger("mikroscan")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s [%(threadName)s] %(message)s")
    )
    logger.addHandler(handler)

    logger.info("=== MikroTik Scanner: new session ===")
    logger.info("log file : %s", path)
    logger.info("python   : %s", sys.version.replace("\n", " "))
    logger.info("platform : %s", platform.platform())
    logger.info("openssl  : %s", ssl.OPENSSL_VERSION)
    return logger, path
