"""Desktop integration: start-with-system and opening links/folders."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import APP_NAME, DISPLAY_NAME

logger = logging.getLogger(__name__)

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def launch_command() -> str:
    """Command line that starts this application again.

    Quoted so paths containing spaces survive the Windows registry round-trip.
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    script = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None
    if script and script.exists():
        return f'"{sys.executable}" "{script}"'
    return f'"{sys.executable}" -m nishizumi_share'


# ---------------------------------------------------------------------------
# Autostart
# ---------------------------------------------------------------------------


def autostart_supported() -> bool:
    return sys.platform in ("win32", "linux")


def set_autostart(enabled: bool) -> bool:
    """Enable or disable start-with-system.  Returns True on success."""
    if sys.platform == "win32":
        return _set_autostart_windows(enabled)
    if sys.platform == "linux":
        return _set_autostart_linux(enabled)
    return False


def get_autostart() -> bool:
    if sys.platform == "win32":
        return _get_autostart_windows()
    if sys.platform == "linux":
        return _linux_autostart_file().exists()
    return False


def _set_autostart_windows(enabled: bool) -> bool:
    try:
        import winreg
    except ImportError:  # pragma: no cover - non-Windows
        return False

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, launch_command())
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
        return True
    except OSError as exc:
        logger.warning("Could not update autostart entry: %s", exc)
        return False


def _get_autostart_windows() -> bool:
    try:
        import winreg
    except ImportError:  # pragma: no cover - non-Windows
        return False

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            return bool(value)
    except OSError:
        return False


def _linux_autostart_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autostart" / "nishizumi-share.desktop"


def _set_autostart_linux(enabled: bool) -> bool:
    target = _linux_autostart_file()
    try:
        if not enabled:
            if target.exists():
                target.unlink()
            return True

        target.parent.mkdir(parents=True, exist_ok=True)
        command = launch_command().replace('"', "")
        target.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={DISPLAY_NAME}\n"
            f"Exec={command}\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-enabled=true\n",
            encoding="utf-8",
        )
        return True
    except OSError as exc:
        logger.warning("Could not update autostart entry: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------


def open_path(path: str | os.PathLike) -> bool:
    """Reveal a file or folder in the system file manager."""
    target = str(path)
    if not os.path.exists(target):
        return False

    try:
        if sys.platform == "win32":
            os.startfile(target)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
        return True
    except (OSError, AttributeError) as exc:
        logger.warning("Could not open %s: %s", target, exc)
        return False
