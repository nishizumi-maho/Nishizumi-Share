"""Optional antivirus scanning.

Scanning is **opt-in**.  When it is switched off — the default — files are
allowed through without ever hashing them.

The important behavioural fix over the 2.x code: when scanning is enabled but
no scanner is installed, the file is *allowed* by default and the reason is
reported.  The previous version treated "no scanner found" as "infected",
which silently blocked every transfer on machines without Defender/ClamAV.
Users who want fail-closed behaviour can set ``av_block_when_unavailable``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .config import Paths, atomic_write_json, get_paths
from .security import sha256_file

CACHE_TTL_SECONDS = 24 * 3600
DEFENDER_TIMEOUT = 120
CLAMAV_TIMEOUT = 180

#: Windows Defender CLI, resolved lazily because %ProgramFiles% varies.
_DEFENDER_RELATIVE = r"Windows Defender\MpCmdRun.exe"


@dataclass(frozen=True)
class ScanResult:
    """Outcome of a scan request."""

    allowed: bool
    status: str  # disabled | clean | infected | unavailable | error
    detail: str = ""

    @property
    def blocked(self) -> bool:
        return not self.allowed

    def describe(self) -> str:
        return f"{self.status}: {self.detail}" if self.detail else self.status


ALLOW_DISABLED = ScanResult(True, "disabled")


def defender_path() -> Optional[str]:
    if sys.platform != "win32":
        return None
    for env_var in ("ProgramFiles", "ProgramW6432"):
        base = os.environ.get(env_var)
        if not base:
            continue
        candidate = os.path.join(base, _DEFENDER_RELATIVE)
        if os.path.exists(candidate):
            return candidate
    return None


def clamav_path() -> Optional[str]:
    for exe in ("clamdscan", "clamscan"):
        found = shutil.which(exe)
        if found:
            return found
    return None


def scanner_available() -> bool:
    return bool(defender_path() or clamav_path())


def _run(cmd: list, timeout: int) -> subprocess.CompletedProcess:
    kwargs = {"capture_output": True, "timeout": timeout}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    return subprocess.run(cmd, **kwargs)


def _decode(result: subprocess.CompletedProcess, limit: int = 300) -> str:
    text = (result.stdout or b"").decode(errors="ignore") + (result.stderr or b"").decode(errors="ignore")
    return text.strip()[:limit]


def scan_with_defender(path: str) -> ScanResult:
    exe = defender_path()
    if not exe:
        return ScanResult(True, "unavailable", "defender_not_installed")

    try:
        result = _run([exe, "-Scan", "-ScanType", "3", "-File", str(path)], DEFENDER_TIMEOUT)
    except subprocess.TimeoutExpired:
        return ScanResult(True, "error", "defender_timeout")
    except OSError as exc:
        return ScanResult(True, "error", f"defender_failed:{exc}")

    # MpCmdRun: 0 = no threat, 2 = threat found (and remediated/quarantined).
    if result.returncode == 0:
        return ScanResult(True, "clean")
    if result.returncode == 2:
        return ScanResult(False, "infected", _decode(result))
    return ScanResult(True, "error", f"defender_rc={result.returncode}:{_decode(result)}")


def scan_with_clamav(path: str) -> ScanResult:
    exe = clamav_path()
    if not exe:
        return ScanResult(True, "unavailable", "clamav_not_installed")

    try:
        result = _run([exe, "--no-summary", str(path)], CLAMAV_TIMEOUT)
    except subprocess.TimeoutExpired:
        return ScanResult(True, "error", "clamav_timeout")
    except OSError as exc:
        return ScanResult(True, "error", f"clamav_failed:{exc}")

    # clamscan/clamdscan: 0 = clean, 1 = virus found, 2 = error.
    if result.returncode == 0:
        return ScanResult(True, "clean")
    if result.returncode == 1:
        return ScanResult(False, "infected", _decode(result))
    return ScanResult(True, "error", f"clamav_rc={result.returncode}:{_decode(result)}")


class AntivirusScanner:
    """Caching front-end over the platform scanners."""

    def __init__(self, paths: Optional[Paths] = None, cache_ttl: int = CACHE_TTL_SECONDS):
        self._paths = paths or get_paths()
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        self._cache: Dict[str, dict] = self._load_cache()

    # -- cache -------------------------------------------------------------

    def _load_cache(self) -> Dict[str, dict]:
        try:
            with open(self._paths.scan_cache, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_cache(self) -> None:
        try:
            atomic_write_json(self._paths.scan_cache, self._cache)
        except OSError:
            pass

    def _cached(self, digest: str) -> Optional[ScanResult]:
        entry = self._cache.get(digest)
        if not entry:
            return None
        if time.time() - entry.get("ts", 0) > self._cache_ttl:
            return None
        return ScanResult(
            bool(entry.get("allowed", True)),
            str(entry.get("status", "clean")),
            str(entry.get("detail", "")),
        )

    def _store(self, digest: str, result: ScanResult) -> None:
        self._cache[digest] = {
            "allowed": result.allowed,
            "status": result.status,
            "detail": result.detail,
            "ts": int(time.time()),
        }
        self._save_cache()

    # -- scanning ----------------------------------------------------------

    def scan(
        self,
        path: str | os.PathLike,
        *,
        enabled: bool,
        block_when_unavailable: bool = False,
    ) -> ScanResult:
        """Scan ``path`` and decide whether it may be transferred."""
        if not enabled:
            return ALLOW_DISABLED

        file_path = Path(path)
        if not file_path.is_file():
            return ScanResult(False, "error", "file_missing")

        try:
            digest = sha256_file(file_path)
        except OSError as exc:
            return ScanResult(False, "error", f"hash_failed:{exc}")

        with self._lock:
            cached = self._cached(digest)
            if cached is not None:
                return self._apply_unavailable_policy(cached, block_when_unavailable)

        if sys.platform == "win32":
            result = scan_with_defender(str(file_path))
        else:
            result = scan_with_clamav(str(file_path))

        # Only cache determinate verdicts; transient errors should be retried.
        if result.status in ("clean", "infected"):
            with self._lock:
                self._store(digest, result)

        return self._apply_unavailable_policy(result, block_when_unavailable)

    @staticmethod
    def _apply_unavailable_policy(result: ScanResult, block_when_unavailable: bool) -> ScanResult:
        """Optionally convert an inconclusive scan into a block."""
        if block_when_unavailable and result.status in ("unavailable", "error"):
            return ScanResult(False, result.status, result.detail or "blocked_by_policy")
        return result
