#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nishizumi Sync Client — Secure (embedded-or-external Tor)
Version: 1.0
Requirements: Python 3.10+, pip install PyQt6 requests pysocks

Features:
 - Option: use embedded Tor (bundled tor/ directory) OR use external tor.exe path
 - Starts embedded tor as a client-only process (no onion service)
 - Validates Tor bootstrap (Bootstrapped 100%) before using it
 - SOCKS5h proxy usage for all requests (requests + pysocks)
 - Secure download flow: .quarantine -> AV scan (Windows Defender or ClamAV) -> atomic move
 - TokenBucket throttling for download
 - Strict path safety checks to avoid traversal
 - Save settings, autostart on Windows (registry Run)
 - Minimal, safe UI (PyQt6)
"""

import os
import sys
import time
import json
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Optional, List
import hashlib
import secrets

import requests
# ensure SOCKS support
try:
    import socks  # pysocks
except Exception:
    pass

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QTextEdit, QCheckBox, QProgressBar, QHBoxLayout, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# -------------------------
# Configuration & constants
# -------------------------
APP_NAME = "Nishizumi-Sync-Client"
CONFIG_DIR = os.path.join(Path.home(), f".{APP_NAME.lower().replace(' ','_')}")
os.makedirs(CONFIG_DIR, exist_ok=True)

SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
TOR_DATA_DIR = os.path.join(CONFIG_DIR, "tor_data_client")
TOR_BUNDLE_DIRNAME = "tor"   # expected bundled tor directory (Tor Expert Bundle)
SOCKS_PORT = 9050
DEFAULT_DL_LIMIT_BPS = 2 * 1024 * 1024
QUARANTINE_DIRNAME = ".quarantine"
SCAN_CACHE_FILE = os.path.join(CONFIG_DIR, "scan_cache.json")

# Logging
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(ch)

# -------------------------
# Default settings
# -------------------------
DEFAULT_SETTINGS = {
    "save_dir": "",
    "team_name": "Team_Setups",
    "peers": [],
    "start_with_system": False,
    "download_limit_bps": DEFAULT_DL_LIMIT_BPS,
    "use_embedded_tor": True,
    "external_tor_path": "",
    "auto_start_tor": True
}

if os.path.exists(SETTINGS_FILE):
    try:
        SETTINGS = json.load(open(SETTINGS_FILE, "r", encoding="utf-8"))
        for k, v in DEFAULT_SETTINGS.items():
            if k not in SETTINGS:
                SETTINGS[k] = v
    except Exception:
        SETTINGS = DEFAULT_SETTINGS.copy()
else:
    SETTINGS = DEFAULT_SETTINGS.copy()

def save_settings():
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f, indent=2)
        try:
            os.chmod(SETTINGS_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        logger.exception("save_settings failed")

# -------------------------
# AV scanning (Defender/Clam)
# -------------------------
def sha256_of_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def load_scan_cache():
    if os.path.exists(SCAN_CACHE_FILE):
        try:
            return json.load(open(SCAN_CACHE_FILE, "r", encoding="utf-8"))
        except Exception:
            return {}
    return {}

_scan_cache = load_scan_cache()

def save_scan_cache(cache):
    try:
        with open(SCAN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        try: os.chmod(SCAN_CACHE_FILE, 0o600)
        except: pass
    except Exception:
        logger.exception("save_scan_cache failed")

DEFENDER_PATH = os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe")

def scan_with_windows_defender(path: str, timeout: int = 60):
    if not os.path.exists(DEFENDER_PATH):
        return False, "defender_not_found"
    cmd = [DEFENDER_PATH, "-Scan", "-ScanType", "3", "-File", path]
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if res.returncode == 0:
            return True, "clean"
        else:
            out = (res.stdout.decode(errors="ignore") + res.stderr.decode(errors="ignore"))[:400]
            return False, f"defender_nonzero:{res.returncode}:{out}"
    except subprocess.TimeoutExpired:
        return False, "defender_timeout"
    except Exception as e:
        return False, f"defender_exception:{str(e)[:200]}"

def scan_with_clamav(path: str, timeout: int = 120):
    for exe in ("clamdscan", "clamscan"):
        if shutil.which(exe):
            cmd = [exe, "--no-summary", path]
            try:
                res = subprocess.run(cmd, capture_output=True, timeout=timeout)
                out = (res.stdout.decode(errors="ignore") + res.stderr.decode(errors="ignore"))[:400]
                if res.returncode == 0:
                    return True, "clean"
                elif res.returncode == 1:
                    return False, f"clam_infected:{out}"
                else:
                    return False, f"clam_error:{res.returncode}:{out}"
            except subprocess.TimeoutExpired:
                return False, "clam_timeout"
            except Exception as e:
                return False, f"clam_exception:{str(e)[:200]}"
    return False, "clam_not_found"

def av_scan_file(path: str, force_scan: bool = False):
    sha = sha256_of_file(path)
    if not sha:
        return False, "hash_error"
    now = int(time.time())
    cached = _scan_cache.get(sha)
    if cached and (now - cached.get("ts", 0) < 24 * 3600):
        return cached.get("clean", False), cached.get("reason", "cached")
    # attempt Defender on Windows, else ClamAV
    if sys.platform.startswith("win"):
        ok, reason = scan_with_windows_defender(path)
        if not ok and reason == "defender_not_found":
            ok, reason = scan_with_clamav(path)
    else:
        ok, reason = scan_with_clamav(path)
    _scan_cache[sha] = {"clean": ok, "reason": reason, "ts": now}
    save_scan_cache(_scan_cache)
    if not ok and force_scan:
        return False, reason
    return ok, reason

# -------------------------
# Utilities
# -------------------------
def is_within_directory(base_dir: str, target_path: str) -> bool:
    try:
        base = Path(base_dir).resolve()
        target = Path(target_path).resolve()
        return base == target or base in target.parents
    except Exception:
        return False

def safe_write_atomic(src: str, dst: str):
    os.replace(src, dst)
    try:
        os.chmod(dst, 0o600)
    except Exception:
        pass

# -------------------------
# TokenBucket for throttling
# -------------------------
class TokenBucket:
    def __init__(self, capacity_bytes: int, fill_rate_bps: float):
        self.capacity = float(capacity_bytes)
        self.tokens = float(capacity_bytes)
        self.fill_rate = float(fill_rate_bps)
        self.timestamp = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.timestamp
        if elapsed <= 0:
            return
        add = elapsed * self.fill_rate
        self.tokens = min(self.capacity, self.tokens + add)
        self.timestamp = now

    def consume(self, num_bytes: int):
        if self.fill_rate <= 0:
            return
        needed = float(num_bytes)
        while True:
            self._refill()
            if self.tokens >= needed:
                self.tokens -= needed
                return
            shortage = needed - self.tokens
            wait = max(0.001, min(0.5, shortage / max(1.0, self.fill_rate)))
            time.sleep(wait)

# -------------------------
# Tor embedded/external management
# -------------------------
def _app_base_path() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def find_bundled_tor() -> Optional[str]:
    base = _app_base_path()
    tor_dir = os.path.join(base, TOR_BUNDLE_DIRNAME)
    if sys.platform.startswith("win"):
        candidate = os.path.join(tor_dir, "tor.exe")
        if os.path.exists(candidate):
            return candidate
    else:
        candidate = os.path.join(tor_dir, "tor")
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

def find_system_tor_in_path() -> Optional[str]:
    exe = "tor.exe" if sys.platform.startswith("win") else "tor"
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(p, exe)
        if os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    return None

class TorProcess:
    def __init__(self, socks_port: int = SOCKS_PORT, external_path: Optional[str] = None, prefer_bundled: bool = True):
        self.socks_port = socks_port
        self.proc: Optional[subprocess.Popen] = None
        self.external_path = external_path
        self.prefer_bundled = prefer_bundled
        self.tor_path = None
        os.makedirs(TOR_DATA_DIR, exist_ok=True)

    def locate(self):
        if self.external_path and os.path.exists(self.external_path):
            self.tor_path = self.external_path
            return
        if self.prefer_bundled:
            b = find_bundled_tor()
            if b:
                self.tor_path = b
                return
            sys_t = find_system_tor_in_path()
            if sys_t:
                self.tor_path = sys_t
                return
        else:
            sys_t = find_system_tor_in_path()
            if sys_t:
                self.tor_path = sys_t
                return
            b = find_bundled_tor()
            if b:
                self.tor_path = b
                return

    def start(self, bootstrap_timeout: int = 30) -> bool:
        if self.proc and self.proc.poll() is None:
            return True
        self.locate()
        if not self.tor_path:
            logger.info("Tor executable not found")
            return False
        args = [self.tor_path, "--SocksPort", str(self.socks_port), "--DataDirectory", TOR_DATA_DIR, "--Log", "notice stdout"]
        try:
            # Start the process and read stdout to watch bootstrap progress
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception as e:
            logger.exception("Failed to start tor: %s", e)
            self.proc = None
            return False

        # Wait for Bootstrapped 100% in stdout (timeout)
        start = time.time()
        ready = False
        try:
            while time.time() - start < bootstrap_timeout:
                if not self.proc:
                    break
                line = self.proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                try:
                    s = line.decode(errors="ignore").strip()
                except Exception:
                    s = str(line)
                logger.debug("tor: %s", s)
                if "Bootstrapped 100%" in s:
                    ready = True
                    break
                # if process died:
                if self.proc.poll() is not None:
                    break
        except Exception:
            pass

        if not ready:
            logger.info("Tor bootstrap not detected within timeout")
            # leave process running for diagnostics (caller may stop it)
            return False
        logger.info("Tor bootstrapped")
        return True

    def stop(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self.proc = None

# -------------------------
# Sync worker
# -------------------------
class SyncWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, str)
    security_alert = pyqtSignal(str)

    def __init__(self, peers: List[str], save_dir: str, team_name: str, dl_limit_bps: int, force_av_scan: bool = True):
        super().__init__()
        self.peers = [p.strip() for p in peers if p.strip()]
        self.save_dir = save_dir
        self.team_name = team_name
        self.running = True
        self.dl_bucket = TokenBucket(int(dl_limit_bps * 2), float(dl_limit_bps))
        self.force_av_scan = force_av_scan

    def stop(self):
        self.running = False

    def is_safe_path(self, base: str, path: str) -> bool:
        try:
            basep = Path(base).resolve()
            pathp = Path(path).resolve()
            return basep == pathp or basep in pathp.parents
        except Exception:
            return False

    def write_log(self, msg: str):
        self.log.emit(msg)

    def run(self):
        session = requests.Session()
        session.proxies.update({"http": f"socks5h://127.0.0.1:{SOCKS_PORT}", "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"})
        session.timeout = 30

        while self.running:
            new_count = 0
            for peer in self.peers:
                if not self.running:
                    break
                if not peer.endswith(".onion"):
                    self.write_log(f"Skipping non-onion peer: {peer}")
                    continue
                peer_url = peer if peer.startswith("http") else f"http://{peer}"
                try:
                    r = session.get(f"{peer_url}/list", timeout=25)
                    if r.status_code != 200:
                        self.write_log(f"Peer {peer} /list returned {r.status_code}")
                        continue
                    data = r.json()
                    if data.get("security_alert"):
                        self.security_alert.emit(f"Peer {peer} reports security alert")
                    map_id = data.get("map_id")
                    map_token = data.get("map_token")
                    if not map_id or not map_token:
                        self.write_log(f"Peer {peer} provided incomplete snapshot")
                        continue
                    files = data.get("files", [])
                    for fdesc in files:
                        if not self.running:
                            break
                        fake = fdesc.get("path")
                        size = int(fdesc.get("size") or 0)
                        fname = os.path.basename(fake)
                        # Save path: <save_dir>/<team_name>/<fname>
                        local_rel = os.path.join(self.team_name, fname)
                        local_path = os.path.join(self.save_dir, local_rel)
                        if os.path.exists(local_path):
                            continue
                        if not self.is_safe_path(self.save_dir, local_path):
                            self.write_log("Unsafe path detected, skipping: %s" % local_path)
                            continue
                        if size and size > 500 * 1024 * 1024:
                            self.write_log(f"Skipping huge file {fname}")
                            continue
                        tmp_dir = os.path.join(self.save_dir, QUARANTINE_DIRNAME)
                        os.makedirs(tmp_dir, exist_ok=True)
                        tmp_path = os.path.join(tmp_dir, secrets.token_hex(8) + "_" + fname)
                        headers = {"Authorization": f"Bearer {map_token}"}
                        try:
                            with session.get(f"{peer_url}/download/{map_id}/{fake}", stream=True, timeout=90, headers=headers) as fr:
                                if fr.status_code != 200:
                                    self.write_log(f"Failed to download {fname}: {fr.status_code}")
                                    try:
                                        if os.path.exists(tmp_path): os.remove(tmp_path)
                                    except: pass
                                    continue
                                dl = 0
                                with open(tmp_path, "wb") as outf:
                                    for chunk in fr.iter_content(chunk_size=64 * 1024):
                                        if not chunk:
                                            break
                                        if not self.running:
                                            break
                                        self.dl_bucket.consume(len(chunk))
                                        outf.write(chunk)
                                        dl += len(chunk)
                                        if size:
                                            pct = int(100 * dl / (size or 1))
                                            self.progress.emit(pct, f"Downloading {fname}")
                                # finished writing
                                try:
                                    os.chmod(tmp_path, 0o600)
                                except Exception:
                                    pass
                                # AV-scan
                                scan_ok, reason = av_scan_file(tmp_path, force_scan=self.force_av_scan)
                                if not scan_ok:
                                    self.write_log(f"AV blocked {fname}: {reason}")
                                    try: os.remove(tmp_path)
                                    except: pass
                                    continue
                                # atomic move into final location
                                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                                safe_write_atomic(tmp_path, local_path)
                                os.utime(local_path, (time.time(), int(time.time())))
                                new_count += 1
                                self.progress.emit(100, f"Saved {fname}")
                                self.write_log(f"Saved {local_rel}")
                        except Exception as e:
                            self.write_log(f"Download exception {fname}: {e}")
                            try:
                                if os.path.exists(tmp_path): os.remove(tmp_path)
                            except: pass
                except Exception as e:
                    self.write_log(f"Peer error {peer}: {e}")
            self.write_log(f"Cycle finished. New files: {new_count}")
            # wait between cycles, but responsive to stop
            for _ in range(30):
                if not self.running:
                    break
                time.sleep(1)

# -------------------------
# Windows autostart helper
# -------------------------
def enable_autostart_windows(enable: bool):
    if not sys.platform.startswith("win"):
        return False
    try:
        import winreg as reg
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, run_key, 0, reg.KEY_SET_VALUE)
        if enable:
            reg.SetValueEx(key, APP_NAME, 0, reg.REG_SZ, f'"{exe}"')
        else:
            try:
                reg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
        reg.CloseKey(key)
        return True
    except Exception:
        return False

# -------------------------
# UI
# -------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(640, 520)
        self.tor_proc: Optional[TorProcess] = None
        self.sync_worker: Optional[SyncWorker] = None
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.status_lbl = QLabel("OFFLINE")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setStyleSheet("background:#8B0000; color:#fff; padding:6px;")
        layout.addWidget(self.status_lbl)

        # Destination folder
        layout.addWidget(QLabel("Destination folder (where setups will be saved):"))
        row = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.btn_dest = QPushButton("Select")
        self.btn_dest.clicked.connect(self.choose_dest)
        row.addWidget(self.dest_edit)
        row.addWidget(self.btn_dest)
        layout.addLayout(row)

        # Team name
        layout.addWidget(QLabel("Team folder name (smart mode):"))
        self.team_edit = QLineEdit()
        layout.addWidget(self.team_edit)

        # Peers (onion)
        layout.addWidget(QLabel("Engineer .onion (one per line):"))
        self.peers_txt = QTextEdit()
        self.peers_txt.setFixedHeight(90)
        layout.addWidget(self.peers_txt)

        # Tor selection
        layout.addWidget(QLabel("Tor mode:"))
        self.chk_embedded = QCheckBox("Use embedded Tor (bundled tor/ folder)")
        self.chk_external = QCheckBox("Use external Tor (point to tor.exe)")
        self.chk_embedded.stateChanged.connect(self.sync_tor_checks)
        self.chk_external.stateChanged.connect(self.sync_tor_checks)
        layout.addWidget(self.chk_embedded)
        layout.addWidget(self.chk_external)

        torpath_row = QHBoxLayout()
        self.tor_path_edit = QLineEdit()
        self.tor_browse_btn = QPushButton("Select tor.exe")
        self.tor_browse_btn.clicked.connect(self.choose_tor_exe)
        torpath_row.addWidget(self.tor_path_edit)
        torpath_row.addWidget(self.tor_browse_btn)
        layout.addLayout(torpath_row)

        # Auto-start Tor toggle
        self.chk_auto_tor = QCheckBox("Auto-start Tor if not running")
        layout.addWidget(self.chk_auto_tor)

        # Autostart with system
        self.chk_autostart = QCheckBox("Start program with system (Windows Run)")
        layout.addWidget(self.chk_autostart)

        # Download limit
        dl_row = QHBoxLayout()
        dl_row.addWidget(QLabel("Download limit (KB/s):"))
        self.limit_edit = QLineEdit(str(int(SETTINGS.get("download_limit_bps", DEFAULT_DL_LIMIT_BPS) // 1024)))
        dl_row.addWidget(self.limit_edit)
        layout.addLayout(dl_row)

        # Buttons: Start Tor, Start Sync
        ctrl_row = QHBoxLayout()
        self.btn_start_tor = QPushButton("START TOR")
        self.btn_start_tor.clicked.connect(self.toggle_tor)
        ctrl_row.addWidget(self.btn_start_tor)
        self.btn_sync = QPushButton("START SYNC")
        self.btn_sync.clicked.connect(self.toggle_sync)
        ctrl_row.addWidget(self.btn_sync)
        layout.addLayout(ctrl_row)

        # Progress + log
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.log_txt = QTextEdit()
        self.log_txt.setReadOnly(True)
        self.log_txt.setFixedHeight(160)
        layout.addWidget(self.log_txt)

        # footer note
        layout.addWidget(QLabel("<i>Note: Tor must run (embedded or external). SOCKS5h is used to preserve .onion anonymity.</i>"))

    def sync_tor_checks(self):
        # mutually exclusive
        if self.sender() == self.chk_embedded and self.chk_embedded.isChecked():
            self.chk_external.setChecked(False)
        if self.sender() == self.chk_external and self.chk_external.isChecked():
            self.chk_embedded.setChecked(False)

    def choose_dest(self):
        d = QFileDialog.getExistingDirectory(self, "Select destination folder")
        if d:
            self.dest_edit.setText(d)

    def choose_tor_exe(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select tor executable", "", "Executables (*.exe);;All Files (*)")
        if f:
            self.tor_path_edit.setText(f)
            SETTINGS["external_tor_path"] = f
            save_settings()

    def append_log(self, msg: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.log_txt.append(f"[{ts}] {msg}")
        except Exception:
            pass
        logger.info(msg)

    def load_settings(self):
        self.dest_edit.setText(SETTINGS.get("save_dir", ""))
        self.team_edit.setText(SETTINGS.get("team_name", "Team_Setups"))
        self.peers_txt.setPlainText("\n".join(SETTINGS.get("peers", [])))
        use_emb = SETTINGS.get("use_embedded_tor", True)
        self.chk_embedded.setChecked(use_emb)
        self.chk_external.setChecked(not use_emb)
        self.tor_path_edit.setText(SETTINGS.get("external_tor_path", ""))
        self.chk_auto_tor.setChecked(SETTINGS.get("auto_start_tor", True))
        self.chk_autostart.setChecked(SETTINGS.get("start_with_system", False))
        self.limit_edit.setText(str(int(SETTINGS.get("download_limit_bps", DEFAULT_DL_LIMIT_BPS) // 1024)))

    def save_current_settings(self):
        SETTINGS["save_dir"] = self.dest_edit.text().strip()
        SETTINGS["team_name"] = self.team_edit.text().strip() or "Team_Setups"
        SETTINGS["peers"] = [p.strip() for p in self.peers_txt.toPlainText().splitlines() if p.strip()]
        SETTINGS["use_embedded_tor"] = self.chk_embedded.isChecked()
        SETTINGS["external_tor_path"] = self.tor_path_edit.text().strip()
        SETTINGS["auto_start_tor"] = self.chk_auto_tor.isChecked()
        SETTINGS["start_with_system"] = self.chk_autostart.isChecked()
        try:
            SETTINGS["download_limit_bps"] = int(self.limit_edit.text().strip()) * 1024
        except Exception:
            SETTINGS["download_limit_bps"] = DEFAULT_DL_LIMIT_BPS
        save_settings()

    def toggle_tor(self):
        # Stop if running
        if self.tor_proc and self.tor_proc.proc:
            self.tor_proc.stop()
            self.tor_proc = None
            self.btn_start_tor.setText("START TOR")
            self.append_log("Stopped embedded/external Tor")
            return

        # Start chosen tor
        use_embedded = self.chk_embedded.isChecked()
        external_path = self.tor_path_edit.text().strip() or None
        prefer_bundled = use_embedded

        self.tor_proc = TorProcess(socks_port=SOCKS_PORT, external_path=external_path, prefer_bundled=prefer_bundled)
        self.append_log("Starting Tor (this may take a few seconds)...")
        ok = self.tor_proc.start(bootstrap_timeout=30)
        if ok:
            self.btn_start_tor.setText("STOP TOR")
            self.append_log(f"Tor is ready (SOCKS5 on 127.0.0.1:{SOCKS_PORT})")
        else:
            self.append_log("Tor did not bootstrap in time or failed. Check tor bundle or external path.")
            QMessageBox.warning(self, "Tor bootstrap", "Tor did not bootstrap within 30 seconds. Check bundled tor or external tor.exe.")
            # keep process running for diagnosis; user may stop it manually

    def toggle_sync(self):
        if self.sync_worker and self.sync_worker.isRunning():
            # stop
            self.sync_worker.stop()
            self.sync_worker = None
            self.btn_sync.setText("START SYNC")
            self.status_lbl.setText("OFFLINE")
            self.status_lbl.setStyleSheet("background:#8B0000; color:#fff; padding:6px;")
            self.append_log("Stopped sync")
            return

        # start
        self.save_current_settings()
        save_dir = SETTINGS.get("save_dir")
        peers = SETTINGS.get("peers", [])
        team = SETTINGS.get("team_name", "Team_Setups")
        dl_limit = SETTINGS.get("download_limit_bps", DEFAULT_DL_LIMIT_BPS)
        auto_start_tor = SETTINGS.get("auto_start_tor", True)

        if not save_dir:
            QMessageBox.warning(self, "Missing folder", "Select destination folder first.")
            return
        if not peers:
            QMessageBox.warning(self, "Missing onion", "Add at least one engineer .onion link.")
            return

        # If user requested auto-start Tor and it's not running, attempt start
        if auto_start_tor and (not self.tor_proc or not (self.tor_proc.proc and self.tor_proc.proc.poll() is None)):
            self.append_log("Auto-starting Tor...")
            self.tor_proc = TorProcess(socks_port=SOCKS_PORT,
                                       external_path=(SETTINGS.get("external_tor_path") or None),
                                       prefer_bundled=SETTINGS.get("use_embedded_tor", True))
            ok = self.tor_proc.start(bootstrap_timeout=30)
            if not ok:
                QMessageBox.warning(self, "Tor not running", "Tor not running and bootstrap failed. Start Tor manually or check bundle.")
                self.append_log("Tor bootstrap failed; aborting sync")
                return
            self.append_log("Tor bootstrap OK")

        # If user enabled autostart program with system (Windows)
        if SETTINGS.get("start_with_system", False) and sys.platform.startswith("win"):
            ok = enable_autostart_windows(True)
            if ok:
                self.append_log("Enabled program autostart in Windows Run")
            else:
                self.append_log("Failed to enable autostart (permissions?)")

        # create quarantine dir with restricted perms
        qdir = os.path.join(save_dir, QUARANTINE_DIRNAME)
        os.makedirs(qdir, exist_ok=True)
        try:
            os.chmod(qdir, 0o700)
        except Exception:
            pass

        # start worker
        self.sync_worker = SyncWorker(peers, save_dir, team, dl_limit, force_av_scan=True)
        self.sync_worker.log.connect(self.append_log)
        self.sync_worker.progress.connect(lambda p, t: (self.progress.setValue(p), self.append_log(t)))
        self.sync_worker.security_alert.connect(lambda m: QMessageBox.critical(self, "Security alert", m))
        self.sync_worker.start()

        self.btn_sync.setText("STOP SYNC")
        self.status_lbl.setText("SYNC ACTIVE")
        self.status_lbl.setStyleSheet("background:#006400; color:#fff; padding:6px;")
        self.append_log("Started sync")

# -------------------------
# Entrypoint
# -------------------------
def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    save_settings()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
