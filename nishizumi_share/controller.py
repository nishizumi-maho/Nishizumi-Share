"""Application controller.

Owns the Tor process, the HTTP server and the sync engine, and exposes a small
imperative API on top of them.  Deliberately Qt-free so it can be driven from
tests or a future headless mode; the GUI adapts the callbacks to signals.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from .avscan import AntivirusScanner
from .config import Settings
from .desktop import set_autostart
from .security import load_dlp_rules
from .server import HttpServer, ShareState, create_app
from .syncclient import SyncEngine
from .tor import TorController, TorError, resolve_tor_binary

logger = logging.getLogger(__name__)

LogCallback = Callable[[str], None]
ProgressCallback = Callable[[int, str], None]


class ControllerError(RuntimeError):
    """A start/stop operation could not be completed."""


class ServiceController:
    """Coordinates Tor, the sharing server and the sync engine."""

    def __init__(
        self,
        settings: Settings,
        *,
        on_log: Optional[LogCallback] = None,
        on_progress: Optional[ProgressCallback] = None,
        on_security_alert: Optional[LogCallback] = None,
        on_file_served: Optional[Callable[[str, int], None]] = None,
    ):
        self.settings = settings
        self.scanner = AntivirusScanner()

        self._log = on_log or (lambda _message: None)
        self._progress = on_progress or (lambda _percent, _message: None)
        self._alert = on_security_alert or (lambda _message: None)

        self.tor = TorController()
        self.state = ShareState(settings, scanner=self.scanner)
        self.state.on_file_served = on_file_served
        self.state.share_dir = str(settings.get("share_dir") or "")
        self.state.set_dlp_rules(load_dlp_rules())

        self._http: Optional[HttpServer] = None
        self._sync_engine: Optional[SyncEngine] = None
        self._sync_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

    # -- state -------------------------------------------------------------

    @property
    def tor_running(self) -> bool:
        return self.tor.is_running()

    @property
    def sharing(self) -> bool:
        with self._lock:
            return self._http is not None and self._http.running

    @property
    def syncing(self) -> bool:
        with self._lock:
            return self._sync_thread is not None and self._sync_thread.is_alive()

    @property
    def onion_address(self) -> Optional[str]:
        return self.tor.onion_address

    @property
    def socks_port(self) -> Optional[int]:
        return self.tor.socks_port

    # -- Tor ---------------------------------------------------------------

    def ensure_tor(self) -> int:
        """Start Tor if it is not already running and return the SOCKS port.

        Both sharing and syncing need Tor, so this is idempotent and shared.
        """
        if self.tor.is_running() and self.tor.socks_port:
            return self.tor.socks_port

        mode = str(self.settings.get("tor_mode") or "embedded")
        binary = resolve_tor_binary(mode, str(self.settings.get("tor_path") or ""))

        if not binary:
            raise ControllerError(
                "Tor was not found. Install the Tor Expert Bundle into the "
                "'tor' folder next to the app, or set an external Tor path in Settings."
            )

        self._log(f"Using Tor: {binary}")
        try:
            self.tor.start(
                binary,
                socks_port=int(self.settings.get("socks_port") or 9050),
                control_port=int(self.settings.get("control_port") or 9051),
                progress=self._log,
            )
        except TorError as exc:
            raise ControllerError(str(exc)) from exc

        assert self.tor.socks_port is not None
        return self.tor.socks_port

    def stop_tor(self) -> None:
        self.tor.stop()

    # -- sharing (server) --------------------------------------------------

    def start_sharing(self) -> str:
        """Start the HTTP server and publish the onion.  Returns the URL."""
        share_dir = str(self.settings.get("share_dir") or "")
        if not share_dir:
            raise ControllerError("Select a folder to share first.")

        import os

        if not os.path.isdir(share_dir):
            raise ControllerError(f"The share folder does not exist:\n{share_dir}")

        self.ensure_tor()

        with self._lock:
            if self._http is not None and self._http.running:
                return self.tor.onion_address or ""

            self.state.share_dir = share_dir
            self.state.set_dlp_rules(load_dlp_rules())
            self.state.refresh_upload_limit()

            port = int(self.settings.get("http_port") or 5000)
            from .tor import find_free_port

            # Bind the local listener to a free port; the onion always maps 80.
            port = find_free_port(port)

            self._log(f"Starting local HTTP server on 127.0.0.1:{port}")
            self._http = HttpServer(create_app(self.state), host="127.0.0.1", port=port)
            self._http.start()

        try:
            onion = self.tor.publish_onion(port)
        except TorError as exc:
            self.stop_sharing()
            raise ControllerError(f"Could not publish the hidden service: {exc}") from exc

        self._log(f"Sharing at {onion}")
        return onion

    def stop_sharing(self) -> None:
        with self._lock:
            http, self._http = self._http, None

        if http is not None:
            http.stop()

        self.tor.remove_onion()
        self._log("Stopped sharing")

    # -- syncing (client) --------------------------------------------------

    def start_sync(self) -> None:
        save_dir = str(self.settings.get("save_dir") or "")
        if not save_dir:
            raise ControllerError("Select a destination folder first.")
        if not self.settings.get("peers"):
            raise ControllerError("Add at least one peer .onion address first.")

        socks_port = self.ensure_tor()

        with self._lock:
            if self._sync_thread is not None and self._sync_thread.is_alive():
                return

            self._sync_engine = SyncEngine(
                self.settings,
                socks_port=socks_port,
                scanner=self.scanner,
                on_log=self._log,
                on_progress=self._progress,
                on_security_alert=self._alert,
            )
            self._sync_thread = threading.Thread(
                target=self._sync_engine.run_forever, name="nishizumi-sync", daemon=True
            )
            self._sync_thread.start()

        self._log("Continuous sync started")

    def stop_sync(self, timeout: float = 10.0) -> None:
        with self._lock:
            engine, thread = self._sync_engine, self._sync_thread
            self._sync_engine, self._sync_thread = None, None

        if engine is not None:
            engine.stop()
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

        self._log("Sync stopped")

    # -- misc --------------------------------------------------------------

    def apply_autostart(self) -> None:
        enabled = bool(self.settings.get("start_with_system"))
        if not set_autostart(enabled):
            self._log("Could not change the start-with-system setting")

    def shutdown(self) -> None:
        """Stop everything.  Safe to call more than once."""
        try:
            self.stop_sync(timeout=3.0)
        except Exception:
            logger.exception("Error stopping sync")
        try:
            self.stop_sharing()
        except Exception:
            logger.exception("Error stopping sharing")
        try:
            self.stop_tor()
        except Exception:
            logger.exception("Error stopping Tor")
