"""Tor process management and control-port client.

Handles locating the binary, launching it with an authenticated control port,
waiting for a real bootstrap, publishing the v3 onion service and shutting
everything down again.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .config import Paths, atomic_write_text, get_paths

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None]

CONTROL_HOST = "127.0.0.1"
CONTROL_TIMEOUT = 15.0
BOOTSTRAP_TIMEOUT = 180
CONTROL_PORT_TIMEOUT = 45

_BOOTSTRAP_PROGRESS_RE = re.compile(r"PROGRESS=(\d+)")
_BOOTSTRAP_SUMMARY_RE = re.compile(r'SUMMARY="([^"]*)"')


class TorError(RuntimeError):
    """Raised when Tor cannot be started or controlled."""


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def resource_root() -> Path:
    """Directory to search for bundled resources.

    Under PyInstaller this is the unpacked bundle; otherwise it is the
    repository/installation root.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parent.parent


def _executable_dir() -> Optional[Path]:
    """Directory containing the running executable (frozen builds only)."""
    if getattr(sys, "frozen", False):
        try:
            return Path(sys.executable).resolve().parent
        except OSError:
            return None
    return None


def tor_executable_name() -> str:
    return "tor.exe" if sys.platform == "win32" else "tor"


def _ensure_executable(path: Path) -> bool:
    """Make sure ``path`` can be executed, adding the bit if it is missing.

    Zip archives and some copy tools drop the executable bit on POSIX, which
    would otherwise make a perfectly good bundled Tor look absent.
    """
    if sys.platform == "win32":
        return path.is_file()
    if os.access(path, os.X_OK):
        return True
    try:
        path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        return False
    return os.access(path, os.X_OK)


def find_bundled_tor() -> Optional[str]:
    """Locate a ``tor/`` folder shipped alongside the app."""
    name = tor_executable_name()
    candidates = []

    for base in (resource_root(), _executable_dir()):
        if base is None:
            continue
        candidates.append(base / "tor" / name)
        # Tor Expert Bundle nests the binary one level deeper.
        candidates.append(base / "tor" / "tor" / name)

    for candidate in candidates:
        if candidate.is_file() and _ensure_executable(candidate):
            return str(candidate)
    return None


def find_system_tor() -> Optional[str]:
    """Locate ``tor`` on PATH or in the usual install locations."""
    from shutil import which

    found = which(tor_executable_name())
    if found:
        return found

    common = [
        r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        r"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        "/usr/bin/tor",
        "/usr/local/bin/tor",
        "/opt/homebrew/bin/tor",
    ]
    for path in common:
        if os.path.isfile(path):
            return path
    return None


def resolve_tor_binary(mode: str, explicit_path: str = "") -> Optional[str]:
    """Pick the Tor binary for the configured mode, with a fallback.

    ``embedded`` prefers the bundled copy, ``external`` prefers the
    user-supplied path; either falls back to the other so a misconfigured
    install still starts when a usable binary exists.
    """
    explicit = str(explicit_path or "").strip()

    if mode == "external":
        if explicit and os.path.isfile(explicit):
            return explicit
        return find_system_tor() or find_bundled_tor()

    bundled = find_bundled_tor()
    if bundled:
        return bundled
    if explicit and os.path.isfile(explicit):
        return explicit
    return find_system_tor()


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


def is_port_open(port: int, host: str = CONTROL_HOST, timeout: float = 0.6) -> bool:
    """True when something is already listening on ``host:port``."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_free_port(preferred: int, host: str = CONTROL_HOST) -> int:
    """Return ``preferred`` if bindable, otherwise an ephemeral free port."""
    for candidate in (preferred, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, candidate))
                return sock.getsockname()[1]
        except OSError:
            continue
    raise TorError("No free TCP port available")


# ---------------------------------------------------------------------------
# Control protocol
# ---------------------------------------------------------------------------


def read_reply(sock: socket.socket, timeout: float = CONTROL_TIMEOUT) -> List[str]:
    """Read one complete control-port reply.

    A reply is a sequence of ``NNN-`` / ``NNN+`` continuation lines terminated
    by a single ``NNN `` line (status code followed by a space).
    """
    sock.settimeout(timeout)
    buffer = b""
    lines: List[str] = []
    in_data_block = False
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        except OSError as exc:
            raise TorError(f"Control connection lost: {exc}") from exc

        if not chunk:
            break
        buffer += chunk

        while b"\r\n" in buffer:
            raw, _, buffer = buffer.partition(b"\r\n")
            line = raw.decode("utf-8", errors="replace")
            lines.append(line)

            if in_data_block:
                # A lone "." closes a 250+ data block.
                if line == ".":
                    in_data_block = False
                continue

            if len(line) >= 4 and line[:3].isdigit():
                separator = line[3]
                if separator == "+":
                    in_data_block = True
                elif separator == " ":
                    return lines

    return lines


def reply_ok(lines: List[str]) -> bool:
    return bool(lines) and any(line.startswith("250") for line in lines)


def parse_key_value(line: str) -> Optional[Tuple[str, str]]:
    """Parse ``250-Key=Value`` into ``(Key, Value)``.

    Splits on the *first* ``=`` only, so base64 payloads with ``=`` padding
    survive intact — the 2.x parser truncated private keys here.
    """
    text = line
    if len(text) >= 4 and text[:3].isdigit() and text[3] in "-+ ":
        text = text[4:]
    if "=" not in text:
        return None
    key, _, value = text.partition("=")
    return key.strip(), value.strip()


class TorController:
    """Owns a Tor child process and its control connection."""

    def __init__(self, paths: Optional[Paths] = None):
        self.paths = (paths or get_paths()).ensure()
        self.process: Optional[subprocess.Popen] = None
        self.control_socket: Optional[socket.socket] = None
        self.socks_port: Optional[int] = None
        self.control_port: Optional[int] = None
        self.onion_address: Optional[str] = None
        self._service_id: Optional[str] = None
        self._lock = threading.RLock()
        self._stop_requested = False
        self._owns_process = False

    # -- lifecycle ---------------------------------------------------------

    def is_running(self) -> bool:
        with self._lock:
            return self.process is not None and self.process.poll() is None

    def start(
        self,
        tor_binary: str,
        *,
        socks_port: int = 9050,
        control_port: int = 9051,
        progress: Optional[ProgressCallback] = None,
        bootstrap_timeout: int = BOOTSTRAP_TIMEOUT,
    ) -> None:
        """Start Tor and block until it has bootstrapped.

        Raises :class:`TorError` on any failure; the child process is always
        cleaned up before the exception propagates.
        """
        report = progress or (lambda _message: None)

        if not tor_binary or not os.path.isfile(tor_binary):
            raise TorError("Tor executable not found. Check the Tor settings.")

        with self._lock:
            self._stop_requested = False

        self.socks_port = find_free_port(socks_port)
        self.control_port = find_free_port(control_port)

        password = self._generate_password()
        hashed = self._hash_password(tor_binary, password)

        args = [
            tor_binary,
            "--SocksPort", f"{CONTROL_HOST}:{self.socks_port}",
            "--ControlPort", f"{CONTROL_HOST}:{self.control_port}",
            "--DataDirectory", str(self.paths.tor_data),
            "--ClientOnly", "1",
            "--AvoidDiskWrites", "1",
        ]

        if hashed:
            args += ["--HashedControlPassword", hashed]
        else:
            # No hashed password available: fall back to cookie auth.
            args += ["--CookieAuthentication", "1"]

        report(f"Starting Tor (SOCKS {self.socks_port}, control {self.control_port})...")

        try:
            self.process = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=0x08000000 if sys.platform == "win32" else 0,
            )
            self._owns_process = True
        except OSError as exc:
            raise TorError(f"Failed to launch Tor: {exc}") from exc

        try:
            self._connect_control()
            self._authenticate(password if hashed else None)
            self._await_bootstrap(report, bootstrap_timeout)
        except BaseException:
            self.stop()
            raise

        report("Tor bootstrapped.")

    def stop(self) -> None:
        """Terminate Tor and close the control connection."""
        with self._lock:
            self._stop_requested = True

            if self.control_socket is not None:
                try:
                    self.control_socket.close()
                except OSError:
                    pass
                self.control_socket = None

            process = self.process
            self.process = None
            self.onion_address = None
            self._service_id = None

        if process is None or not self._owns_process:
            return

        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.warning("Tor process did not exit after kill()")
        except OSError as exc:
            logger.warning("Error stopping Tor: %s", exc)
        finally:
            self._owns_process = False

    # -- control helpers ---------------------------------------------------

    @staticmethod
    def _generate_password() -> str:
        # token_urlsafe only yields [A-Za-z0-9_-], so the value can be passed
        # on the command line and inside a quoted AUTHENTICATE without escaping.
        import secrets

        return secrets.token_urlsafe(24)

    @staticmethod
    def _hash_password(tor_binary: str, password: str) -> Optional[str]:
        """Ask Tor to hash the control password; None if that fails."""
        try:
            result = subprocess.run(
                [tor_binary, "--hash-password", password],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=0x08000000 if sys.platform == "win32" else 0,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not hash control password: %s", exc)
            return None

        output = (result.stdout or "") + (result.stderr or "")
        for line in output.splitlines():
            candidate = line.strip()
            # Tor's hashed passwords are always "16:<hex>".
            if candidate.startswith("16:") and len(candidate) > 20:
                return candidate
        return None

    def _connect_control(self) -> None:
        deadline = time.monotonic() + CONTROL_PORT_TIMEOUT

        while time.monotonic() < deadline:
            with self._lock:
                if self._stop_requested:
                    raise TorError("Startup cancelled")

            if self.process is not None and self.process.poll() is not None:
                raise TorError(
                    "Tor exited during start-up. Check that the binary is valid "
                    "and the data directory is writable."
                )

            try:
                sock = socket.create_connection((CONTROL_HOST, self.control_port), timeout=5)
                self.control_socket = sock
                return
            except OSError:
                time.sleep(0.5)

        raise TorError("Tor control port did not become reachable.")

    def send_command(self, command: str) -> List[str]:
        """Send one control command and return the reply lines."""
        with self._lock:
            sock = self.control_socket
        if sock is None:
            raise TorError("Not connected to the Tor control port")

        if not command.endswith("\r\n"):
            command += "\r\n"

        try:
            sock.sendall(command.encode("utf-8"))
        except OSError as exc:
            raise TorError(f"Failed to send control command: {exc}") from exc

        return read_reply(sock)

    def _authenticate(self, password: Optional[str]) -> None:
        if password:
            if reply_ok(self.send_command(f'AUTHENTICATE "{password}"')):
                return
            logger.info("Password authentication rejected, trying cookie auth")

        cookie = self.paths.tor_data / "control_auth_cookie"
        if cookie.exists():
            try:
                cookie_hex = cookie.read_bytes().hex()
            except OSError as exc:
                raise TorError(f"Cannot read Tor auth cookie: {exc}") from exc
            if reply_ok(self.send_command(f"AUTHENTICATE {cookie_hex}")):
                return

        if reply_ok(self.send_command("AUTHENTICATE")):
            return

        raise TorError("Could not authenticate to the Tor control port.")

    def _await_bootstrap(self, report: ProgressCallback, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        last_progress = -1

        while time.monotonic() < deadline:
            with self._lock:
                if self._stop_requested:
                    raise TorError("Startup cancelled")

            if self.process is not None and self.process.poll() is not None:
                raise TorError("Tor exited while bootstrapping.")

            lines = self.send_command("GETINFO status/bootstrap-phase")
            percent, summary = self._parse_bootstrap(lines)

            if percent is not None and percent != last_progress:
                last_progress = percent
                report(f"Tor bootstrap {percent}% — {summary}" if summary else f"Tor bootstrap {percent}%")

            if percent is not None and percent >= 100:
                return

            time.sleep(1.0)

        raise TorError(
            f"Tor did not finish bootstrapping within {timeout}s. "
            "Check the network connection or try again."
        )

    @staticmethod
    def _parse_bootstrap(lines: List[str]) -> Tuple[Optional[int], str]:
        for line in lines:
            if "BOOTSTRAP" not in line.upper():
                continue
            match = _BOOTSTRAP_PROGRESS_RE.search(line)
            if not match:
                continue
            summary_match = _BOOTSTRAP_SUMMARY_RE.search(line)
            return int(match.group(1)), summary_match.group(1) if summary_match else ""
        return None, ""

    # -- onion service -----------------------------------------------------

    def publish_onion(self, local_port: int, *, virtual_port: int = 80) -> str:
        """Publish (or republish) the hidden service and return its URL.

        The private key is persisted so the ``.onion`` address survives
        restarts.  A stored key that Tor rejects is discarded and replaced.
        """
        stored_key = self._read_onion_key()
        service_id = None
        private_key = None

        if stored_key:
            lines = self.send_command(f"ADD_ONION {stored_key} Port={virtual_port},{local_port}")
            service_id, private_key = self._parse_add_onion(lines)
            if not service_id:
                logger.warning("Stored onion key was rejected by Tor; generating a new identity")

        if not service_id:
            lines = self.send_command(
                f"ADD_ONION NEW:ED25519-V3 Port={virtual_port},{local_port}"
            )
            service_id, private_key = self._parse_add_onion(lines)
            if private_key:
                self._write_onion_key(private_key)

        if not service_id:
            raise TorError("Tor refused to create the hidden service.")

        self._service_id = service_id
        self.onion_address = f"http://{service_id}.onion"
        return self.onion_address

    def remove_onion(self) -> None:
        if not self._service_id:
            return
        try:
            self.send_command(f"DEL_ONION {self._service_id}")
        except TorError:
            pass
        self._service_id = None
        self.onion_address = None

    @staticmethod
    def _parse_add_onion(lines: List[str]) -> Tuple[Optional[str], Optional[str]]:
        service_id = None
        private_key = None
        for line in lines:
            parsed = parse_key_value(line)
            if not parsed:
                continue
            key, value = parsed
            if key == "ServiceID":
                service_id = value
            elif key == "PrivateKey":
                private_key = value
        return service_id, private_key

    def _read_onion_key(self) -> Optional[str]:
        try:
            if not self.paths.onion_key.exists():
                return None
            key = self.paths.onion_key.read_text(encoding="utf-8").strip()
        except OSError:
            return None

        if not key:
            return None
        # Older builds stored the blob without its key-type prefix.
        if ":" not in key:
            return f"ED25519-V3:{key}"
        return key

    def _write_onion_key(self, private_key: str) -> None:
        try:
            atomic_write_text(self.paths.onion_key, private_key)
        except OSError as exc:
            logger.warning("Could not persist onion key: %s", exc)

    def burn_identity(self) -> None:
        """Delete the stored onion key after backing it up."""
        self.remove_onion()
        try:
            if self.paths.onion_key.exists():
                key = self.paths.onion_key.read_text(encoding="utf-8")
                atomic_write_text(self.paths.onion_key_backup, key)
                self.paths.onion_key.unlink()
        except OSError as exc:
            logger.warning("Could not remove onion key: %s", exc)


def socks_proxies(socks_port: int) -> dict:
    """requests-style proxy mapping.

    ``socks5h`` keeps hostname resolution inside Tor, which is required for
    ``.onion`` addresses to resolve at all.
    """
    url = f"socks5h://{CONTROL_HOST}:{socks_port}"
    return {"http": url, "https": url}
