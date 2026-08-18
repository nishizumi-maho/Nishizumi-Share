"""The sharing server: Flask routes plus a controllable HTTP server.

The server hands out *snapshots*.  A snapshot is an immutable listing of the
share directory together with a bearer token; downloads are only possible by
quoting a snapshot id and its token, and snapshots expire.  Real paths never
leave the process.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from flask import Flask, Response, jsonify, request

from .avscan import AntivirusScanner
from .config import Settings
from .security import (
    NameMapper,
    is_within_directory,
    load_or_create_name_key,
    mask_name,
    new_token,
    tokens_equal,
)
from .throttle import SlidingWindowRateLimiter, TokenBucket

logger = logging.getLogger(__name__)

SNAPSHOT_TTL_SECONDS = 600
MAX_SNAPSHOTS = 32
MAX_FILES_PER_SNAPSHOT = 20_000
STREAM_CHUNK_SIZE = 64 * 1024


@dataclass
class Snapshot:
    """An immutable listing plus the token that unlocks it."""

    snapshot_id: str
    token: str
    created_at: float
    entries: Dict[str, str]  # public name -> absolute real path
    files: List[dict]

    def expired(self, now: Optional[float] = None, ttl: int = SNAPSHOT_TTL_SECONDS) -> bool:
        return (now or time.time()) - self.created_at > ttl


@dataclass
class OneTimeToken:
    token: str
    snapshot_id: Optional[str]
    expires_at: float
    note: str = ""
    used: bool = False


@dataclass
class ServerStats:
    files_served: int = 0
    bytes_served: int = 0
    listings_served: int = 0
    denied_requests: int = 0


class ShareState:
    """Everything the routes need, guarded by one lock.

    Instances are shared between WSGI worker threads and the GUI thread, so
    every mutation goes through :attr:`_lock`.
    """

    def __init__(
        self,
        settings: Settings,
        scanner: Optional[AntivirusScanner] = None,
        snapshot_ttl: int = SNAPSHOT_TTL_SECONDS,
    ):
        self.settings = settings
        self.scanner = scanner or AntivirusScanner()
        self.name_mapper = NameMapper(load_or_create_name_key())
        self.snapshot_ttl = int(snapshot_ttl)

        self._lock = threading.RLock()
        self._share_dir: str = ""
        self._snapshots: Dict[str, Snapshot] = {}
        self._one_time_tokens: Dict[str, OneTimeToken] = {}
        self._upload_bucket = TokenBucket.from_rate(settings.get("upload_limit_bps"))

        self.stats = ServerStats()
        self.security_alert = False

        #: Called (from a worker thread) whenever a file finishes streaming.
        self.on_file_served: Optional[Callable[[str, int], None]] = None

    # -- configuration -----------------------------------------------------

    @property
    def share_dir(self) -> str:
        with self._lock:
            return self._share_dir

    @share_dir.setter
    def share_dir(self, value: str) -> None:
        with self._lock:
            self._share_dir = str(value or "")
            # Old snapshots point into the previous directory; drop them.
            self._snapshots.clear()

    def refresh_upload_limit(self) -> None:
        with self._lock:
            self._upload_bucket = TokenBucket.from_rate(self.settings.get("upload_limit_bps"))

    @property
    def upload_bucket(self) -> TokenBucket:
        with self._lock:
            return self._upload_bucket

    def set_dlp_rules(self, rules: Dict[str, str]) -> None:
        self.name_mapper.set_rules(rules)

    # -- snapshots ---------------------------------------------------------

    def _prune_locked(self) -> None:
        now = time.time()
        for snapshot_id in [
            sid for sid, snap in self._snapshots.items() if snap.expired(now, self.snapshot_ttl)
        ]:
            self._snapshots.pop(snapshot_id, None)
        for token in [t for t, ot in self._one_time_tokens.items() if now > ot.expires_at]:
            self._one_time_tokens.pop(token, None)

        # Bound memory even if a peer requests listings in a tight loop.
        while len(self._snapshots) > MAX_SNAPSHOTS:
            oldest = min(self._snapshots.values(), key=lambda snap: snap.created_at)
            self._snapshots.pop(oldest.snapshot_id, None)

    def build_snapshot(self) -> Optional[Snapshot]:
        """Walk the share directory and register a new snapshot."""
        share_dir = self.share_dir
        if not share_dir or not os.path.isdir(share_dir):
            return None

        entries: Dict[str, str] = {}
        files: List[dict] = []
        now = time.time()

        for root, dirnames, filenames in os.walk(share_dir, followlinks=False):
            # Never descend into the client-side quarantine folder.
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

            for filename in filenames:
                if filename.startswith("."):
                    continue
                if len(files) >= MAX_FILES_PER_SNAPSHOT:
                    logger.warning("Share directory exceeds %d files; listing truncated", MAX_FILES_PER_SNAPSHOT)
                    break

                full_path = os.path.join(root, filename)
                if not is_within_directory(share_dir, full_path):
                    logger.warning("Skipping file outside share dir: %s", mask_name(filename))
                    continue

                try:
                    stat = os.stat(full_path)
                except OSError:
                    continue
                if not os.path.isfile(full_path):
                    continue

                rel_path = os.path.relpath(full_path, share_dir).replace("\\", "/")
                public_name = self.name_mapper.public_name(rel_path)

                entries[public_name] = full_path
                files.append(
                    {
                        "path": public_name,
                        "size": stat.st_size,
                        "mtime": int(stat.st_mtime),
                        "age_hours": max(0, int((now - stat.st_mtime) // 3600)),
                    }
                )

        snapshot = Snapshot(
            snapshot_id=new_token(8),
            token=new_token(24),
            created_at=now,
            entries=entries,
            files=files,
        )

        with self._lock:
            self._prune_locked()
            self._snapshots[snapshot.snapshot_id] = snapshot
            self.stats.listings_served += 1

        return snapshot

    def get_snapshot(self, snapshot_id: str) -> Optional[Snapshot]:
        with self._lock:
            self._prune_locked()
            return self._snapshots.get(snapshot_id)

    # -- one-time tokens ---------------------------------------------------

    def issue_one_time_token(self, ttl_seconds: int, note: str = "") -> OneTimeToken:
        """Mint a token bound to a fresh snapshot of the current share."""
        snapshot = self.build_snapshot()
        token = OneTimeToken(
            token=new_token(28),
            snapshot_id=snapshot.snapshot_id if snapshot else None,
            expires_at=time.time() + max(60, int(ttl_seconds)),
            note=note,
        )
        with self._lock:
            self._prune_locked()
            self._one_time_tokens[token.token] = token
        return token

    def authorise(self, snapshot_id: str, presented_token: str) -> bool:
        """Check a bearer token against the snapshot token or a one-time token."""
        with self._lock:
            self._prune_locked()

            snapshot = self._snapshots.get(snapshot_id)
            if snapshot is not None and tokens_equal(presented_token, snapshot.token):
                return True

            for one_time in self._one_time_tokens.values():
                if not tokens_equal(presented_token, one_time.token):
                    continue
                if time.time() > one_time.expires_at:
                    return False
                if one_time.snapshot_id and one_time.snapshot_id != snapshot_id:
                    return False
                return True

            return False

    def list_token_ok(self, presented: str) -> bool:
        """Validate the optional shared secret guarding ``/list``."""
        if not self.settings.get("require_list_token"):
            return True
        expected = str(self.settings.get("list_access_token") or "")
        if not expected:
            # Configured to require a token but none set: fail closed.
            return False
        return tokens_equal(presented, expected)

    def record_served(self, name: str, size: int) -> None:
        with self._lock:
            self.stats.files_served += 1
            self.stats.bytes_served += max(0, size)
        callback = self.on_file_served
        if callback is not None:
            try:
                callback(name, size)
            except Exception:  # pragma: no cover - UI callback must never break streaming
                logger.exception("on_file_served callback failed")

    def record_denied(self) -> None:
        with self._lock:
            self.stats.denied_requests += 1


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------


def _bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return ""


def create_app(state: ShareState) -> Flask:
    """Build the Flask app bound to ``state``."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    limiter = SlidingWindowRateLimiter(max_requests=600, window_seconds=60)

    @app.after_request
    def _harden(response: Response) -> Response:
        # The client is a script, not a browser, but these cost nothing and
        # protect anyone who opens the onion in Tor Browser.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Server", "nishizumi")
        return response

    @app.get("/health")
    def health() -> Response:
        return jsonify({"status": "ok", "ready": bool(state.share_dir)})

    @app.get("/list")
    def list_files():
        if not limiter.allow():
            state.record_denied()
            return jsonify({"error": "rate_limited"}), 429

        if not state.list_token_ok(_bearer_token()):
            state.record_denied()
            return jsonify({"error": "unauthorized"}), 401

        snapshot = state.build_snapshot()
        if snapshot is None:
            return jsonify({"error": "not_ready"}), 503

        return jsonify(
            {
                "protocol": 3,
                "files": snapshot.files,
                "map_id": snapshot.snapshot_id,
                "map_token": snapshot.token,
                "expires_in": state.snapshot_ttl,
                "security_alert": bool(state.security_alert),
            }
        )

    @app.get("/download/<map_id>/<path:public_name>")
    def download_file(map_id: str, public_name: str):
        if not limiter.allow():
            state.record_denied()
            return jsonify({"error": "rate_limited"}), 429

        if not state.authorise(map_id, _bearer_token()):
            state.record_denied()
            return jsonify({"error": "unauthorized"}), 401

        snapshot = state.get_snapshot(map_id)
        if snapshot is None:
            return jsonify({"error": "snapshot_expired"}), 404

        # The public name must be one this snapshot actually published, so an
        # attacker cannot ask for an arbitrary path.
        real_path = snapshot.entries.get(public_name)
        if not real_path:
            return jsonify({"error": "not_found"}), 404

        share_dir = state.share_dir
        if not share_dir or not is_within_directory(share_dir, real_path):
            logger.warning("Rejected path outside share dir: %s", mask_name(public_name))
            state.record_denied()
            return jsonify({"error": "forbidden"}), 403

        if not os.path.isfile(real_path):
            return jsonify({"error": "not_found"}), 404

        scan = state.scanner.scan(
            real_path,
            enabled=bool(state.settings.get("av_enabled")),
            block_when_unavailable=bool(state.settings.get("av_block_when_unavailable")),
        )
        if scan.blocked:
            logger.warning("AV blocked %s (%s)", mask_name(os.path.basename(real_path)), scan.describe())
            state.record_denied()
            return jsonify({"error": "blocked_by_av", "reason": scan.status}), 403

        try:
            size = os.path.getsize(real_path)
        except OSError:
            return jsonify({"error": "not_found"}), 404

        bucket = state.upload_bucket
        served_name = os.path.basename(public_name)

        def generate():
            sent = 0
            try:
                with open(real_path, "rb") as handle:
                    while True:
                        chunk = handle.read(STREAM_CHUNK_SIZE)
                        if not chunk:
                            break
                        bucket.consume(len(chunk))
                        sent += len(chunk)
                        yield chunk
            except OSError:
                logger.exception("Error streaming %s", mask_name(served_name))
                return
            finally:
                if sent:
                    state.record_served(served_name, sent)

        response = Response(generate(), mimetype="application/octet-stream")
        # Content-Length lets the client show real progress and detect truncation.
        response.headers["Content-Length"] = str(size)
        response.headers["Content-Disposition"] = f'attachment; filename="{_safe_header_value(served_name)}"'
        return response

    @app.errorhandler(404)
    def _not_found(_error):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(500)
    def _server_error(_error):  # pragma: no cover - defensive
        return jsonify({"error": "internal_error"}), 500

    return app


def _safe_header_value(value: str) -> str:
    """Strip characters that would let a filename break out of the header."""
    return "".join(ch for ch in str(value) if 32 <= ord(ch) < 127 and ch not in '"\\') or "download"


# ---------------------------------------------------------------------------
# Controllable HTTP server
# ---------------------------------------------------------------------------


class HttpServer:
    """Runs the Flask app in a background thread with a real stop().

    The 2.x code called ``os._exit(0)`` to stop serving, which killed the whole
    GUI.  This wraps waitress (falling back to werkzeug) so the listener can be
    closed and restarted in-process.
    """

    def __init__(self, app: Flask, host: str = "127.0.0.1", port: int = 5000, threads: int = 6):
        self.app = app
        self.host = host
        self.port = port
        self.threads = threads
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._backend = ""

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._server = self._create_server()
            self._thread = threading.Thread(
                target=self._serve, name="nishizumi-http", daemon=True
            )
            self._thread.start()

    def _create_server(self):
        try:
            from waitress.server import create_server  # type: ignore

            self._backend = "waitress"
            return create_server(
                self.app,
                host=self.host,
                port=self.port,
                threads=self.threads,
                ident="nishizumi",
                clear_untrusted_proxy_headers=True,
            )
        except ImportError:
            from werkzeug.serving import make_server

            self._backend = "werkzeug"
            return make_server(self.host, self.port, self.app, threaded=True)

    def _serve(self) -> None:
        server = self._server
        if server is None:
            return
        try:
            if self._backend == "waitress":
                server.run()
            else:
                server.serve_forever()
        except OSError as exc:
            # Expected when stop() closes the listening socket underneath us.
            logger.debug("HTTP server loop ended: %s", exc)
        except Exception:  # pragma: no cover - defensive
            logger.exception("HTTP server crashed")

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            server, thread = self._server, self._thread
            self._server, self._thread = None, None

        if server is not None:
            try:
                if self._backend == "waitress":
                    server.close()
                else:
                    server.shutdown()
                    server.server_close()
            except Exception:  # pragma: no cover - defensive
                logger.exception("Error stopping HTTP server")

        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
