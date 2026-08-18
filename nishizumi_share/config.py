"""Filesystem layout and persisted settings.

Two responsibilities live here:

* :class:`Paths` — where the app keeps its state, per platform.
* :class:`Settings` — a validated, atomically-persisted settings store.

Both are explicit objects rather than import-time globals so tests can point
them at a temporary directory.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from . import APP_NAME

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

SETTINGS_SCHEMA_VERSION = 3

MB = 1024 * 1024

DEFAULT_DOWNLOAD_LIMIT_BPS = 2 * MB
DEFAULT_UPLOAD_LIMIT_BPS = 2 * MB
DEFAULT_MAX_FILE_SIZE = 200 * MB

#: Hard ceiling for a single file, independent of what the user configures.
ABSOLUTE_MAX_FILE_SIZE = 8 * 1024 * MB  # 8 GiB

DEFAULT_SETTINGS: Dict[str, Any] = {
    "schema_version": SETTINGS_SCHEMA_VERSION,
    # Tor
    "tor_mode": "embedded",  # "embedded" | "external"
    "tor_path": "",
    "socks_port": 9050,
    "control_port": 9051,
    "http_port": 5000,
    # Bandwidth / limits
    "download_limit_bps": DEFAULT_DOWNLOAD_LIMIT_BPS,
    "upload_limit_bps": DEFAULT_UPLOAD_LIMIT_BPS,
    "max_file_size": DEFAULT_MAX_FILE_SIZE,
    # Antivirus (opt-in)
    "av_enabled": False,
    "av_block_when_unavailable": False,
    # Sharing / syncing
    "peers": [],
    "share_dir": "",
    "save_dir": "",
    "sync_mode": "smart",  # "smart" | "mirror" | "flat"
    "team_folder": "Team_Setups",
    "only_setup_files": False,
    "sync_interval_seconds": 30,
    # Access control
    "require_list_token": False,
    "list_access_token": "",
    # Desktop integration
    "start_with_system": False,
    # Updates
    "auto_check_updates": True,
    "update_via_tor": True,
    "update_prerelease": False,
}

#: Settings that must never be written to disk in plain text by mistake.
_SECRET_KEYS = {"list_access_token"}

_VALID_TOR_MODES = ("embedded", "external")
_VALID_SYNC_MODES = ("smart", "mirror", "flat")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def default_config_root() -> Path:
    """Return the per-user configuration directory for this platform.

    ``NISHIZUMI_CONFIG_DIR`` overrides the platform default, which is what the
    test-suite and portable installations use.
    """
    override = os.environ.get("NISHIZUMI_CONFIG_DIR")
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME

    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "nishizumi-share"


#: Config directories used by earlier releases, newest first.  Settings are
#: imported from the first one that exists when no current config is present.
LEGACY_CONFIG_ROOTS = (
    Path.home() / f".{APP_NAME}",
    Path.home() / ".nishizumi-sync-client",
    Path.home() / ".nishizumisyncserverlite",
)


class Paths:
    """Resolved locations of every file the application persists."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.settings = self.root / "settings.json"
        self.onion_key = self.root / "onion_private_key"
        self.onion_key_backup = self.root / "onion_private_key.bak"
        self.peers = self.root / "team_peers.txt"
        self.dlp_rules = self.root / "security_rules.txt"
        self.name_key = self.root / "name_key"
        self.scan_cache = self.root / "scan_cache.json"
        self.token_log = self.root / "one_time_token_log.jsonl"
        self.tor_data = self.root / "tor_data"
        self.logs = self.root / "logs"
        self.update_cache = self.root / "updates"

    def ensure(self) -> "Paths":
        """Create the directory tree, tightening permissions where supported."""
        for directory in (self.root, self.tor_data, self.logs, self.update_cache):
            directory.mkdir(parents=True, exist_ok=True)
            _restrict_dir(directory)
        return self

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Paths(root={self.root!r})"


def _restrict_dir(path: Path) -> None:
    """Best-effort 0700 on a directory (no-op where chmod is meaningless)."""
    try:
        os.chmod(path, 0o700)
    except (OSError, NotImplementedError):
        pass


_paths_lock = threading.Lock()
_paths: Optional[Paths] = None


def get_paths() -> Paths:
    """Return the process-wide :class:`Paths`, creating it on first use."""
    global _paths
    with _paths_lock:
        if _paths is None:
            _paths = Paths(default_config_root()).ensure()
        return _paths


def set_config_root(root: Path) -> Paths:
    """Point the process at a different config root (used by tests)."""
    global _paths
    with _paths_lock:
        _paths = Paths(Path(root)).ensure()
        return _paths


# ---------------------------------------------------------------------------
# Atomic writes
# ---------------------------------------------------------------------------


def atomic_write_text(path: Path, data: str, *, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically.

    The temp file is created in the destination directory so :func:`os.replace`
    stays on one filesystem and is therefore atomic.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_name, mode)
        except (OSError, NotImplementedError):
            pass
        os.replace(tmp_name, path)
    except BaseException:
        # Never leave a stray temp file behind on failure.
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, obj: Any, *, mode: int = 0o600) -> None:
    atomic_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False), mode=mode)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _as_int(value: Any, fallback: int, *, minimum: int = 0, maximum: Optional[int] = None) -> int:
    """Coerce ``value`` to an int inside ``[minimum, maximum]``.

    Older settings files stored several of these as strings, so parsing has to
    be forgiving rather than raising.
    """
    try:
        result = int(value)
    except (TypeError, ValueError):
        return fallback
    if result < minimum:
        return minimum
    if maximum is not None and result > maximum:
        return maximum
    return result


def _as_bool(value: Any, fallback: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off"):
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return fallback


def _as_str_list(value: Any) -> list:
    if isinstance(value, str):
        candidates: Iterable[str] = value.splitlines()
    elif isinstance(value, (list, tuple)):
        candidates = [str(item) for item in value]
    else:
        return []
    seen = set()
    result = []
    for item in candidates:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def _as_port(value: Any, fallback: int) -> int:
    return _as_int(value, fallback, minimum=1, maximum=65535)


class Settings:
    """Validated settings backed by a JSON file.

    Every read goes through :meth:`get`, and every write is validated by
    :func:`normalise`, so malformed or hand-edited files degrade to defaults
    instead of crashing the app at start-up.
    """

    def __init__(self, path: Path, data: Optional[Dict[str, Any]] = None):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = normalise(data or {})

    # -- construction ------------------------------------------------------

    @classmethod
    def load(cls, paths: Optional[Paths] = None) -> "Settings":
        """Load settings, falling back to defaults and migrating old installs."""
        paths = paths or get_paths()
        raw: Dict[str, Any] = {}

        if paths.settings.exists():
            raw = _read_json_dict(paths.settings)
        else:
            legacy = _find_legacy_settings()
            if legacy:
                raw = legacy

        settings = cls(paths.settings, raw)
        # Persist immediately so the on-disk file always matches the current
        # schema (and so a migrated legacy config is not re-read next launch).
        settings.save()
        return settings

    # -- access ------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self._data:
                return self._data[key]
            if default is not None:
                return default
            return DEFAULT_SETTINGS.get(key)

    def set(self, key: str, value: Any) -> None:
        self.update({key: value})

    def update(self, values: Dict[str, Any]) -> None:
        with self._lock:
            merged = dict(self._data)
            merged.update(values)
            self._data = normalise(merged)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._data)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    # -- persistence -------------------------------------------------------

    def save(self) -> bool:
        """Write settings to disk.  Returns ``False`` if the write failed."""
        with self._lock:
            payload = dict(self._data)
        try:
            atomic_write_json(self.path, payload)
            return True
        except OSError:
            return False


def normalise(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate and validate a raw settings mapping.

    Unknown keys are dropped, legacy keys are translated, and every value is
    coerced into range.  The result always contains exactly the keys of
    :data:`DEFAULT_SETTINGS`.
    """
    raw = dict(raw or {})
    result = dict(DEFAULT_SETTINGS)

    # --- migrate pre-v3 keys ---------------------------------------------
    if "tor_mode" not in raw and "use_embedded_tor" in raw:
        raw["tor_mode"] = "embedded" if _as_bool(raw.get("use_embedded_tor"), True) else "external"

    if "av_enabled" not in raw:
        # v2 called this force_av_scan and additionally had a global kill switch
        # (AV_DISABLE_GLOBAL) that silently overrode it.  Honour the user's
        # stored preference now that the kill switch is gone.
        if "force_av_scan" in raw:
            raw["av_enabled"] = _as_bool(raw.get("force_av_scan"), False)

    if "external_tor_path" in raw and not raw.get("tor_path"):
        raw["tor_path"] = raw.get("external_tor_path")

    if "team_name" in raw and "team_folder" not in raw:
        raw["team_folder"] = raw.get("team_name")

    if "start_with_windows" in raw and "start_with_system" not in raw:
        raw["start_with_system"] = raw.get("start_with_windows")

    # v2 encoded sync mode as 3 (smart) / 2 (mirror).
    sync_mode_raw = raw.get("sync_mode", DEFAULT_SETTINGS["sync_mode"])
    if isinstance(sync_mode_raw, (int, float)) or (
        isinstance(sync_mode_raw, str) and sync_mode_raw.strip().isdigit()
    ):
        numeric = _as_int(sync_mode_raw, 3)
        raw["sync_mode"] = {3: "smart", 2: "mirror"}.get(numeric, "smart")

    # --- validate ---------------------------------------------------------
    tor_mode = str(raw.get("tor_mode", "embedded")).strip().lower()
    result["tor_mode"] = tor_mode if tor_mode in _VALID_TOR_MODES else "embedded"

    sync_mode = str(raw.get("sync_mode", "smart")).strip().lower()
    result["sync_mode"] = sync_mode if sync_mode in _VALID_SYNC_MODES else "smart"

    result["tor_path"] = str(raw.get("tor_path") or "").strip()
    result["socks_port"] = _as_port(raw.get("socks_port"), DEFAULT_SETTINGS["socks_port"])
    result["control_port"] = _as_port(raw.get("control_port"), DEFAULT_SETTINGS["control_port"])
    result["http_port"] = _as_port(raw.get("http_port"), DEFAULT_SETTINGS["http_port"])

    # 0 means "unlimited" for the bandwidth caps.
    result["download_limit_bps"] = _as_int(
        raw.get("download_limit_bps"), DEFAULT_DOWNLOAD_LIMIT_BPS, minimum=0
    )
    result["upload_limit_bps"] = _as_int(
        raw.get("upload_limit_bps"), DEFAULT_UPLOAD_LIMIT_BPS, minimum=0
    )
    result["max_file_size"] = _as_int(
        raw.get("max_file_size"),
        DEFAULT_MAX_FILE_SIZE,
        minimum=1,
        maximum=ABSOLUTE_MAX_FILE_SIZE,
    )

    result["av_enabled"] = _as_bool(raw.get("av_enabled"), False)
    result["av_block_when_unavailable"] = _as_bool(raw.get("av_block_when_unavailable"), False)

    result["peers"] = _as_str_list(raw.get("peers"))
    result["share_dir"] = str(raw.get("share_dir") or "")
    result["save_dir"] = str(raw.get("save_dir") or "")
    result["team_folder"] = _safe_folder_name(raw.get("team_folder"), DEFAULT_SETTINGS["team_folder"])
    result["only_setup_files"] = _as_bool(raw.get("only_setup_files"), False)
    result["sync_interval_seconds"] = _as_int(
        raw.get("sync_interval_seconds"), 30, minimum=5, maximum=3600
    )

    result["require_list_token"] = _as_bool(raw.get("require_list_token"), False)
    result["list_access_token"] = str(raw.get("list_access_token") or "").strip()

    result["start_with_system"] = _as_bool(raw.get("start_with_system"), False)
    result["auto_check_updates"] = _as_bool(raw.get("auto_check_updates"), True)
    result["update_via_tor"] = _as_bool(raw.get("update_via_tor"), True)
    result["update_prerelease"] = _as_bool(raw.get("update_prerelease"), False)

    result["schema_version"] = SETTINGS_SCHEMA_VERSION
    return result


def _safe_folder_name(value: Any, fallback: str) -> str:
    """Reduce a user-supplied folder name to a single safe path component."""
    text = str(value or "").strip()
    if not text:
        return fallback
    # Reject separators and traversal outright rather than trying to repair them.
    text = text.replace("\\", "/").split("/")[-1].strip()
    if not text or text in (".", "..") or text.startswith("."):
        return fallback
    forbidden = '<>:"|?*\x00'
    cleaned = "".join("_" if ch in forbidden or ord(ch) < 32 else ch for ch in text)
    cleaned = cleaned.strip(" .")
    return cleaned[:64] or fallback


def _read_json_dict(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _find_legacy_settings() -> Optional[Dict[str, Any]]:
    """Return settings from the newest legacy install directory, if any."""
    for root in LEGACY_CONFIG_ROOTS:
        candidate = root / "settings.json"
        if candidate.exists():
            data = _read_json_dict(candidate)
            if data:
                return data
    return None


def migrate_legacy_state(paths: Optional[Paths] = None) -> list:
    """Copy onion keys / peers / DLP rules from a pre-3.0 install.

    Only files that do not already exist in the new location are copied, so
    running this repeatedly is safe.  Returns the list of copied file names.
    """
    paths = (paths or get_paths()).ensure()
    copied = []

    interesting = {
        "onion_private_key": paths.onion_key,
        "onion_key": paths.onion_key,
        "team_peers.txt": paths.peers,
        "security_rules.txt": paths.dlp_rules,
        "admin_key": paths.name_key,
    }

    for root in LEGACY_CONFIG_ROOTS:
        if not root.is_dir() or root.resolve() == paths.root.resolve():
            continue
        for source_name, destination in interesting.items():
            source = root / source_name
            if source.is_file() and not destination.exists():
                try:
                    shutil.copyfile(source, destination)
                    try:
                        os.chmod(destination, 0o600)
                    except (OSError, NotImplementedError):
                        pass
                    copied.append(destination.name)
                except OSError:
                    continue
    return copied
