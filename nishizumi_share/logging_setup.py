"""Logging configuration.

Logs go to a rotating file next to the settings, and to the console when one
is attached.  Frozen GUI builds on Windows have no usable stdout, so the
console handler is skipped there.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from .config import Paths, get_paths

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
MAX_LOG_BYTES = 1024 * 1024
LOG_BACKUPS = 3

_configured = False


def configure_logging(level: int = logging.INFO, paths: Optional[Paths] = None) -> Path:
    """Set up root logging once and return the log file path."""
    global _configured

    paths = (paths or get_paths()).ensure()
    log_file = paths.logs / "nishizumi.log"

    if _configured:
        return log_file

    root = logging.getLogger()
    root.setLevel(level)

    formatter = logging.Formatter(LOG_FORMAT)

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError:
        # A read-only config dir must not prevent the app from starting.
        pass

    if sys.stderr is not None:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root.addHandler(console)

    # Waitress logs every connection at INFO; that is noise for this app.
    logging.getLogger("waitress").setLevel(logging.ERROR)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _configured = True
    return log_file


class QtLogBridge(logging.Handler):
    """Forwards log records to a callback (used to mirror logs into the UI)."""

    def __init__(self, callback):
        super().__init__()
        self._callback = callback
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._callback(self.format(record), record.levelno)
        except Exception:  # pragma: no cover - never let logging break the app
            pass
