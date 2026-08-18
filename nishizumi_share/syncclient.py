"""Peer polling and file downloading.

Everything here is Qt-free: the engine reports progress through plain
callbacks and stops when the caller sets its :class:`threading.Event`.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional
from urllib.parse import quote, urlparse, urlunparse

from .avscan import AntivirusScanner
from .config import Settings
from .security import safe_join, sanitize_component, strip_hmac_suffix
from .throttle import TokenBucket
from .tor import socks_proxies

logger = logging.getLogger(__name__)

QUARANTINE_DIRNAME = ".quarantine"
DOWNLOAD_CHUNK_SIZE = 64 * 1024
LIST_TIMEOUT = 60
DOWNLOAD_TIMEOUT = 300
SETUP_EXTENSIONS = (".sto", ".olap", ".blap", ".rpy")

LogCallback = Callable[[str], None]
ProgressCallback = Callable[[int, str], None]


class PeerError(RuntimeError):
    """A peer could not be reached or returned something unusable."""


# ---------------------------------------------------------------------------
# Peer addresses
# ---------------------------------------------------------------------------


def normalise_peer_url(peer: str) -> Optional[str]:
    """Normalise a peer address, rejecting anything that is not an onion.

    Accepts bare hostnames, full URLs, trailing slashes and explicit ports.
    Returns ``None`` for non-onion addresses so traffic can never leak to the
    clearnet — the 2.x check (``peer.endswith('.onion')``) silently dropped
    valid URLs with a trailing slash and accepted nothing else.
    """
    text = str(peer or "").strip()
    if not text:
        return None

    if "://" not in text:
        text = f"http://{text}"

    try:
        parsed = urlparse(text)
    except ValueError:
        return None

    if parsed.scheme not in ("http", "https"):
        return None

    hostname = (parsed.hostname or "").lower()
    if not hostname.endswith(".onion"):
        return None

    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    return urlunparse((parsed.scheme, netloc, "", "", "", ""))


# ---------------------------------------------------------------------------
# Local path planning
# ---------------------------------------------------------------------------


def plan_local_path(
    public_name: str,
    *,
    save_dir: str,
    mode: str = "smart",
    team_folder: str = "Team_Setups",
) -> Optional[Path]:
    """Decide where a peer-advertised file should land locally.

    Returns ``None`` when the peer-supplied name cannot be mapped safely.
    The name comes from the network, so every component is sanitised and the
    final path is confined to ``save_dir``.
    """
    if not save_dir:
        return None

    cleaned = strip_hmac_suffix(str(public_name or "")).replace("\\", "/")
    parts = [p for p in cleaned.split("/") if p not in ("", ".", "..")]
    if not parts:
        return None

    safe_parts = [sanitize_component(part) for part in parts]
    filename = safe_parts[-1]
    directories = safe_parts[:-1]
    team = sanitize_component(team_folder) if team_folder else "Team_Setups"

    if mode == "smart":
        if directories:
            car = directories[0]
            rest = directories[1:]
            relative = [car, team, *rest, filename]
        else:
            relative = ["_General", team, filename]
    elif mode == "mirror":
        relative = [team, *directories, filename]
    else:  # "flat" — mirror the source tree exactly
        relative = [*directories, filename]

    return safe_join(save_dir, *relative)


def is_setup_file(name: str) -> bool:
    return str(name).lower().endswith(SETUP_EXTENSIONS)


# ---------------------------------------------------------------------------
# Peer client
# ---------------------------------------------------------------------------


@dataclass
class RemoteFile:
    public_name: str
    size: int
    mtime: int = 0


@dataclass
class PeerListing:
    map_id: str
    map_token: str
    files: List[RemoteFile] = field(default_factory=list)
    security_alert: bool = False


class PeerClient:
    """Talks to one peer over the Tor SOCKS proxy."""

    def __init__(self, socks_port: int, access_token: str = ""):
        import requests  # imported lazily so the core imports without it

        self._session = requests.Session()
        self._session.proxies.update(socks_proxies(socks_port))
        self._session.headers["User-Agent"] = "nishizumi-share"
        self._access_token = str(access_token or "")

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # pragma: no cover - defensive
            pass

    def fetch_listing(self, peer_url: str) -> PeerListing:
        headers = {}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        try:
            response = self._session.get(f"{peer_url}/list", timeout=LIST_TIMEOUT, headers=headers)
        except Exception as exc:  # requests raises a wide family of errors
            raise PeerError(f"unreachable ({type(exc).__name__})") from exc

        if response.status_code == 401:
            raise PeerError("access token rejected")
        if response.status_code == 503:
            raise PeerError("peer has no share folder configured")
        if response.status_code != 200:
            raise PeerError(f"HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise PeerError("invalid JSON listing") from exc

        map_id = str(payload.get("map_id") or "")
        map_token = str(payload.get("map_token") or "")
        if not map_id or not map_token:
            raise PeerError("incomplete listing")

        files = []
        for item in payload.get("files") or []:
            if not isinstance(item, dict):
                continue
            name = item.get("path")
            if not name or not isinstance(name, str):
                continue
            try:
                size = int(item.get("size", -1))
            except (TypeError, ValueError):
                size = -1
            try:
                mtime = int(item.get("mtime", 0))
            except (TypeError, ValueError):
                mtime = 0
            files.append(RemoteFile(public_name=name, size=size, mtime=mtime))

        return PeerListing(
            map_id=map_id,
            map_token=map_token,
            files=files,
            security_alert=bool(payload.get("security_alert")),
        )

    def download(
        self,
        peer_url: str,
        listing: PeerListing,
        remote: RemoteFile,
        destination: Path,
        *,
        bucket: TokenBucket,
        stop_event: threading.Event,
        on_progress: Optional[ProgressCallback] = None,
    ) -> int:
        """Download one file into ``destination`` (already inside quarantine).

        Returns the number of bytes written.  Raises :class:`PeerError` if the
        transfer fails or the received size does not match what was announced.
        """
        url = f"{peer_url}/download/{quote(listing.map_id, safe='')}/{quote(remote.public_name, safe='/')}"
        headers = {"Authorization": f"Bearer {listing.map_token}"}
        display_name = destination.name

        try:
            with self._session.get(
                url, headers=headers, stream=True, timeout=DOWNLOAD_TIMEOUT
            ) as response:
                if response.status_code == 403:
                    raise PeerError("refused by peer (antivirus or policy)")
                if response.status_code in (401, 404):
                    raise PeerError(f"snapshot expired (HTTP {response.status_code})")
                if response.status_code != 200:
                    raise PeerError(f"HTTP {response.status_code}")

                expected = _expected_size(response, remote)
                written = 0

                with open(destination, "wb") as handle:
                    for chunk in response.iter_content(DOWNLOAD_CHUNK_SIZE):
                        if stop_event.is_set():
                            raise PeerError("cancelled")
                        if not chunk:
                            continue
                        bucket.consume(len(chunk), should_continue=lambda: not stop_event.is_set())
                        handle.write(chunk)
                        written += len(chunk)

                        if on_progress and expected > 0:
                            percent = min(100, int(100 * written / expected))
                            on_progress(percent, f"Downloading {display_name}")

        except PeerError:
            raise
        except Exception as exc:
            raise PeerError(f"transfer failed ({type(exc).__name__})") from exc

        if expected > 0 and written != expected:
            raise PeerError(f"truncated transfer ({written}/{expected} bytes)")

        return written


def _expected_size(response, remote: RemoteFile) -> int:
    """Prefer the response's Content-Length, fall back to the listing size."""
    header = response.headers.get("Content-Length")
    if header:
        try:
            return int(header)
        except (TypeError, ValueError):
            pass
    return remote.size if remote.size and remote.size > 0 else 0


# ---------------------------------------------------------------------------
# Sync engine
# ---------------------------------------------------------------------------


@dataclass
class SyncStats:
    downloaded: int = 0
    skipped: int = 0
    failed: int = 0


class SyncEngine:
    """Repeatedly pulls new files from every configured peer."""

    def __init__(
        self,
        settings: Settings,
        *,
        socks_port: int,
        scanner: Optional[AntivirusScanner] = None,
        on_log: Optional[LogCallback] = None,
        on_progress: Optional[ProgressCallback] = None,
        on_security_alert: Optional[LogCallback] = None,
    ):
        self.settings = settings
        self.socks_port = socks_port
        self.scanner = scanner or AntivirusScanner()
        self.stop_event = threading.Event()

        self._log = on_log or (lambda _message: None)
        self._progress = on_progress or (lambda _percent, _message: None)
        self._alert = on_security_alert or (lambda _message: None)

    def stop(self) -> None:
        self.stop_event.set()

    # -- helpers -----------------------------------------------------------

    def _quarantine_dir(self, save_dir: str) -> Path:
        path = Path(save_dir) / QUARANTINE_DIRNAME
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except (OSError, NotImplementedError):
            pass
        return path

    @staticmethod
    def cleanup_quarantine(save_dir: str, max_age_seconds: int = 6 * 3600) -> int:
        """Delete stale partial downloads left behind by a previous run."""
        quarantine = Path(save_dir) / QUARANTINE_DIRNAME
        if not quarantine.is_dir():
            return 0

        removed = 0
        cutoff = time.time() - max_age_seconds
        for entry in quarantine.iterdir():
            try:
                if entry.is_file() and entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def _needs_download(self, remote: RemoteFile, local_path: Path) -> bool:
        if not local_path.exists():
            return True
        if remote.size < 0:
            return False
        try:
            return local_path.stat().st_size != remote.size
        except OSError:
            return True

    # -- main loop ---------------------------------------------------------

    def run_forever(self) -> None:
        """Poll peers until :meth:`stop` is called."""
        save_dir = str(self.settings.get("save_dir") or "")
        if save_dir:
            removed = self.cleanup_quarantine(save_dir)
            if removed:
                self._log(f"Cleared {removed} stale quarantine file(s)")

        while not self.stop_event.is_set():
            try:
                stats = self.run_once()
                self._log(
                    f"Cycle complete — {stats.downloaded} new, "
                    f"{stats.skipped} up to date, {stats.failed} failed"
                )
            except Exception:
                logger.exception("Sync cycle failed")
                self._log("Sync cycle failed unexpectedly; retrying next cycle")

            interval = int(self.settings.get("sync_interval_seconds") or 30)
            # Event.wait returns as soon as stop() is called, so shutdown is instant.
            self.stop_event.wait(timeout=interval)

    def run_once(self) -> SyncStats:
        """Run a single sync pass across all peers."""
        stats = SyncStats()

        save_dir = str(self.settings.get("save_dir") or "")
        if not save_dir or not os.path.isdir(save_dir):
            self._log("Destination folder is not set or does not exist")
            return stats

        peers = [normalise_peer_url(p) for p in (self.settings.get("peers") or [])]
        valid_peers = [p for p in peers if p]
        if len(valid_peers) != len(peers):
            self._log(f"Ignored {len(peers) - len(valid_peers)} invalid (non-.onion) peer entries")
        if not valid_peers:
            self._log("No valid .onion peers configured")
            return stats

        bucket = TokenBucket.from_rate(self.settings.get("download_limit_bps"))
        quarantine = self._quarantine_dir(save_dir)
        client = PeerClient(self.socks_port, str(self.settings.get("list_access_token") or ""))

        try:
            for peer_url in valid_peers:
                if self.stop_event.is_set():
                    break
                self._sync_peer(client, peer_url, save_dir, quarantine, bucket, stats)
        finally:
            client.close()

        return stats

    def _sync_peer(
        self,
        client: PeerClient,
        peer_url: str,
        save_dir: str,
        quarantine: Path,
        bucket: TokenBucket,
        stats: SyncStats,
    ) -> None:
        short_peer = _short_peer(peer_url)

        try:
            listing = client.fetch_listing(peer_url)
        except PeerError as exc:
            stats.failed += 1
            self._log(f"Peer {short_peer}: {exc}")
            return

        if listing.security_alert:
            self._alert(f"Peer {short_peer} reported a security alert")

        mode = str(self.settings.get("sync_mode") or "smart")
        team_folder = str(self.settings.get("team_folder") or "Team_Setups")
        only_setups = bool(self.settings.get("only_setup_files"))
        max_size = int(self.settings.get("max_file_size") or 0)

        for remote in listing.files:
            if self.stop_event.is_set():
                return

            if only_setups and not is_setup_file(strip_hmac_suffix(remote.public_name)):
                continue

            local_path = plan_local_path(
                remote.public_name, save_dir=save_dir, mode=mode, team_folder=team_folder
            )
            if local_path is None:
                stats.failed += 1
                self._log(f"Peer {short_peer}: rejected unsafe filename")
                continue

            if not self._needs_download(remote, local_path):
                stats.skipped += 1
                continue

            if max_size and remote.size > max_size:
                stats.skipped += 1
                self._log(f"Skipping {local_path.name}: larger than the configured limit")
                continue

            if self._download_one(client, peer_url, listing, remote, local_path, quarantine, bucket):
                stats.downloaded += 1
            else:
                stats.failed += 1

    def _download_one(
        self,
        client: PeerClient,
        peer_url: str,
        listing: PeerListing,
        remote: RemoteFile,
        local_path: Path,
        quarantine: Path,
        bucket: TokenBucket,
    ) -> bool:
        handle, temp_name = tempfile.mkstemp(dir=str(quarantine), prefix="dl_", suffix=".part")
        os.close(handle)
        temp_path = Path(temp_name)

        try:
            client.download(
                peer_url,
                listing,
                remote,
                temp_path,
                bucket=bucket,
                stop_event=self.stop_event,
                on_progress=self._progress,
            )

            scan = self.scanner.scan(
                temp_path,
                enabled=bool(self.settings.get("av_enabled")),
                block_when_unavailable=bool(self.settings.get("av_block_when_unavailable")),
            )
            if scan.blocked:
                self._log(f"Antivirus blocked {local_path.name} ({scan.describe()})")
                return False

            local_path.parent.mkdir(parents=True, exist_ok=True)
            _move_atomic(temp_path, local_path)

            self._progress(100, f"Saved {local_path.name}")
            self._log(f"Saved {local_path.name}")
            return True

        except PeerError as exc:
            if str(exc) != "cancelled":
                self._log(f"Failed {local_path.name}: {exc}")
            return False
        except OSError as exc:
            self._log(f"Failed to store {local_path.name}: {exc}")
            return False
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass


def _move_atomic(source: Path, destination: Path) -> None:
    """Move within the same volume when possible, else copy and replace."""
    try:
        os.replace(source, destination)
    except OSError:
        # Cross-device move: copy to a sibling temp file, then swap it in.
        temp_destination = destination.with_name(destination.name + ".incoming")
        shutil.copyfile(source, temp_destination)
        os.replace(temp_destination, destination)
        try:
            source.unlink()
        except OSError:
            pass

    try:
        os.chmod(destination, 0o600)
    except (OSError, NotImplementedError):
        pass


def _short_peer(peer_url: str) -> str:
    """Abbreviate an onion address for logging."""
    host = urlparse(peer_url).hostname or peer_url
    return f"{host[:10]}…{host[-12:]}" if len(host) > 24 else host
