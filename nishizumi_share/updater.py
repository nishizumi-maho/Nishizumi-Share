"""Automatic updates from GitHub Releases.

Flow: query the Releases API, compare versions, download the single setup
installer, verify its SHA-256 against the release checksum file, then hand off
to the installer in silent mode and quit so it can replace the running files.

The download is executed afterwards, so verification is mandatory: an update
whose checksum cannot be confirmed is discarded.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import GITHUB_REPO, __version__
from .config import Paths, get_paths
from .security import sha256_file

logger = logging.getLogger(__name__)

API_ROOT = "https://api.github.com"
RELEASES_URL = f"{API_ROOT}/repos/{GITHUB_REPO}/releases"
RELEASE_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"
CHECKSUM_ASSET_NAME = "SHA256SUMS.txt"
NETWORK_TIMEOUT = 60
MAX_INSTALLER_BYTES = 512 * 1024 * 1024

ProgressCallback = Callable[[int, str], None]

_VERSION_RE = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?(?:[-+](?P<pre>.+))?$"
)


class UpdateError(RuntimeError):
    """Raised when an update cannot be checked, downloaded or verified."""


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------


def parse_version(text: str) -> Optional[Tuple[int, int, int, Tuple]]:
    """Parse a semver-ish string into a sortable tuple.

    Returns ``None`` for unparseable input.  A release sorts *above* any
    prerelease with the same numbers (3.0.0 > 3.0.0-rc1).
    """
    match = _VERSION_RE.match(str(text or "").strip())
    if not match:
        return None

    major = int(match.group("major"))
    minor = int(match.group("minor") or 0)
    patch = int(match.group("patch") or 0)
    pre = match.group("pre")

    if not pre:
        # Empty tuple sorts before any non-empty one, so invert with a flag.
        return (major, minor, patch, (1,))

    identifiers: List = [0]
    for part in re.split(r"[.]", pre):
        identifiers.append((0, int(part)) if part.isdigit() else (1, part))
    return (major, minor, patch, tuple(identifiers))


def is_newer(candidate: str, current: str) -> bool:
    """True when ``candidate`` is a strictly newer version than ``current``."""
    parsed_candidate = parse_version(candidate)
    parsed_current = parse_version(current)
    if parsed_candidate is None or parsed_current is None:
        return False
    return parsed_candidate > parsed_current


# ---------------------------------------------------------------------------
# Release model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    tag: str
    notes: str
    asset_name: str
    asset_url: str
    asset_size: int
    checksum_url: str = ""
    expected_sha256: str = ""
    html_url: str = RELEASE_PAGE

    @property
    def can_auto_install(self) -> bool:
        """Only the Windows setup installer can be applied automatically."""
        return sys.platform == "win32" and self.asset_name.lower().endswith(".exe")


def installer_asset_pattern() -> str:
    """Filename fragment identifying this platform's installer asset."""
    return "setup" if sys.platform == "win32" else ""


def _select_installer_asset(assets: Sequence[dict]) -> Optional[dict]:
    """Pick the single setup installer from a release's assets."""
    if sys.platform != "win32":
        return None

    candidates = [
        asset
        for asset in assets
        if str(asset.get("name", "")).lower().endswith(".exe")
        and "setup" in str(asset.get("name", "")).lower()
    ]
    if not candidates:
        candidates = [a for a in assets if str(a.get("name", "")).lower().endswith(".exe")]

    return candidates[0] if candidates else None


def _select_checksum_asset(assets: Sequence[dict]) -> Optional[dict]:
    for asset in assets:
        if str(asset.get("name", "")).lower() == CHECKSUM_ASSET_NAME.lower():
            return asset
    return None


def _asset_digest(asset: dict) -> str:
    """Read the ``digest`` field GitHub attaches to newer assets."""
    digest = str(asset.get("digest") or "")
    if digest.lower().startswith("sha256:"):
        return digest.split(":", 1)[1].strip().lower()
    return ""


def parse_checksums(text: str) -> Dict[str, str]:
    """Parse ``sha256  filename`` lines into ``{filename: sha256}``."""
    result: Dict[str, str] = {}
    for line in str(text).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest = parts[0].strip().lower()
        # The GNU format marks binary files with a leading '*'.
        name = os.path.basename(parts[-1].lstrip("*").strip())
        if re.fullmatch(r"[0-9a-f]{64}", digest) and name:
            result[name] = digest
    return result


def _release_to_update(release: dict) -> Optional[UpdateInfo]:
    tag = str(release.get("tag_name") or "")
    version = tag.lstrip("vV")
    if not version:
        return None

    assets = release.get("assets") or []
    installer = _select_installer_asset(assets)
    checksums = _select_checksum_asset(assets)

    return UpdateInfo(
        version=version,
        tag=tag,
        notes=str(release.get("body") or ""),
        asset_name=str(installer.get("name")) if installer else "",
        asset_url=str(installer.get("browser_download_url")) if installer else "",
        asset_size=int(installer.get("size") or 0) if installer else 0,
        checksum_url=str(checksums.get("browser_download_url")) if checksums else "",
        expected_sha256=_asset_digest(installer) if installer else "",
        html_url=str(release.get("html_url") or RELEASE_PAGE),
    )


# ---------------------------------------------------------------------------
# Updater
# ---------------------------------------------------------------------------


class Updater:
    """Checks for, downloads and applies updates."""

    def __init__(
        self,
        current_version: str = __version__,
        *,
        paths: Optional[Paths] = None,
        proxies: Optional[Dict[str, str]] = None,
        allow_prerelease: bool = False,
    ):
        self.current_version = current_version
        self.paths = (paths or get_paths()).ensure()
        self.proxies = proxies or None
        self.allow_prerelease = allow_prerelease

    # -- network -----------------------------------------------------------

    def _session(self):
        import requests

        session = requests.Session()
        session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": f"nishizumi-share/{self.current_version}",
            }
        )
        if self.proxies:
            session.proxies.update(self.proxies)
        return session

    def fetch_releases(self) -> List[dict]:
        session = self._session()
        try:
            url = RELEASES_URL if self.allow_prerelease else f"{RELEASES_URL}/latest"
            response = session.get(url, timeout=NETWORK_TIMEOUT)

            if response.status_code == 404:
                return []
            if response.status_code == 403:
                raise UpdateError("GitHub rate limit reached; try again later")
            if response.status_code != 200:
                raise UpdateError(f"GitHub returned HTTP {response.status_code}")

            payload = response.json()
        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateError(f"Could not reach GitHub ({type(exc).__name__})") from exc
        finally:
            session.close()

        if isinstance(payload, dict):
            return [payload]
        return [item for item in payload if isinstance(item, dict)]

    def check(self) -> Optional[UpdateInfo]:
        """Return the newest applicable release, or None if up to date."""
        releases = self.fetch_releases()

        best: Optional[UpdateInfo] = None
        for release in releases:
            if release.get("draft"):
                continue
            if release.get("prerelease") and not self.allow_prerelease:
                continue

            info = _release_to_update(release)
            if info is None or not is_newer(info.version, self.current_version):
                continue
            if best is None or is_newer(info.version, best.version):
                best = info

        return best

    # -- download ----------------------------------------------------------

    def _fetch_expected_checksum(self, info: UpdateInfo) -> str:
        """Resolve the expected digest from the checksum asset or asset digest."""
        if info.expected_sha256:
            return info.expected_sha256.lower()

        if not info.checksum_url:
            return ""

        session = self._session()
        try:
            response = session.get(info.checksum_url, timeout=NETWORK_TIMEOUT)
            if response.status_code != 200:
                return ""
            return parse_checksums(response.text).get(info.asset_name, "")
        except Exception:
            logger.warning("Could not download %s", CHECKSUM_ASSET_NAME)
            return ""
        finally:
            session.close()

    def download(self, info: UpdateInfo, progress: Optional[ProgressCallback] = None) -> Path:
        """Download and verify the installer, returning its local path.

        Raises :class:`UpdateError` if the download fails or the checksum does
        not match — the file is deleted in that case.
        """
        if not info.asset_url:
            raise UpdateError("This release has no installer for your platform")

        report = progress or (lambda _percent, _message: None)
        expected = self._fetch_expected_checksum(info)
        if not expected:
            raise UpdateError(
                "The release is missing a SHA-256 checksum. Refusing to run an "
                "unverified installer — please update manually."
            )

        destination = self.paths.update_cache / info.asset_name
        if destination.exists():
            try:
                if sha256_file(destination).lower() == expected:
                    report(100, "Update already downloaded")
                    return destination
                destination.unlink()
            except OSError:
                pass

        session = self._session()
        handle, temp_name = tempfile.mkstemp(dir=str(self.paths.update_cache), suffix=".part")
        os.close(handle)
        temp_path = Path(temp_name)

        try:
            report(0, f"Downloading {info.asset_name}")
            with session.get(info.asset_url, stream=True, timeout=NETWORK_TIMEOUT) as response:
                if response.status_code != 200:
                    raise UpdateError(f"Download failed (HTTP {response.status_code})")

                total = int(response.headers.get("Content-Length") or info.asset_size or 0)
                if total > MAX_INSTALLER_BYTES:
                    raise UpdateError("Installer is unexpectedly large; aborting")

                written = 0
                with open(temp_path, "wb") as output:
                    for chunk in response.iter_content(256 * 1024):
                        if not chunk:
                            continue
                        written += len(chunk)
                        if written > MAX_INSTALLER_BYTES:
                            raise UpdateError("Installer exceeded the maximum allowed size")
                        output.write(chunk)
                        if total:
                            report(min(99, int(100 * written / total)), f"Downloading {info.asset_name}")

            actual = sha256_file(temp_path).lower()
            if actual != expected:
                raise UpdateError(
                    "Checksum mismatch — the download was corrupted or tampered with."
                )

            os.replace(temp_path, destination)
            report(100, "Update verified")
            return destination

        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateError(f"Download failed ({type(exc).__name__})") from exc
        finally:
            session.close()
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    # -- install -----------------------------------------------------------

    @staticmethod
    def launch_installer(installer_path: Path, *, silent: bool = True) -> None:
        """Start the installer and return immediately.

        The caller must quit right afterwards so the installer can replace the
        running executable.
        """
        installer_path = Path(installer_path)
        if not installer_path.is_file():
            raise UpdateError("Installer file is missing")

        if sys.platform != "win32":
            raise UpdateError("Automatic installation is only supported on Windows")

        # Inno Setup silent switches; RESTARTAPPLICATIONS relaunches the app.
        args = [str(installer_path)]
        if silent:
            args += [
                "/VERYSILENT",
                "/SUPPRESSMSGBOXES",
                "/NORESTART",
                "/CLOSEAPPLICATIONS",
                "/RESTARTAPPLICATIONS",
            ]

        try:
            subprocess.Popen(
                args,
                close_fds=True,
                creationflags=0x00000008,  # DETACHED_PROCESS
            )
        except OSError as exc:
            raise UpdateError(f"Could not start the installer: {exc}") from exc


def check_in_background(
    updater: Updater,
    on_result: Callable[[Optional[UpdateInfo], Optional[str]], None],
) -> threading.Thread:
    """Run :meth:`Updater.check` off the UI thread.

    ``on_result`` receives ``(info, error_message)``; exactly one is non-None.
    """

    def worker() -> None:
        try:
            on_result(updater.check(), None)
        except UpdateError as exc:
            on_result(None, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Update check failed")
            on_result(None, f"Unexpected error: {exc}")

    thread = threading.Thread(target=worker, name="nishizumi-update-check", daemon=True)
    thread.start()
    return thread
