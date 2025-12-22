#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nishizumi Sync Server — Secure Lite Version
Com Start With Windows, Onion Persistente e UI minimalista
"""

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import shutil
import socket
import subprocess
import logging
from pathlib import Path
from typing import Dict

from flask import Flask, jsonify, Response, request

# waiter
try:
    from waitress import serve
except:
    serve = None

# UI
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QFileDialog, QTextEdit, QHBoxLayout, QMessageBox, QCheckBox, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
APP_NAME = "NishizumiSyncServerLite"

CONFIG_DIR = os.path.join(Path.home(), f".{APP_NAME.lower()}")
os.makedirs(CONFIG_DIR, exist_ok=True)

SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
SHARE_DIR_FILE = os.path.join(CONFIG_DIR, "share_dir.txt")
ONION_KEY_FILE = os.path.join(CONFIG_DIR, "onion_key")
SCAN_CACHE_FILE = os.path.join(CONFIG_DIR, "scan_cache.json")
TOR_DATA_DIR = os.path.join(CONFIG_DIR, "tor_data")
os.makedirs(TOR_DATA_DIR, exist_ok=True)

FLASK_PORT = 5000
SOCKS_PORT = 9050
CTRL_PORT = 9051

DEFAULT_UPLOAD_LIMIT = 2 * 1024 * 1024  # 2 MB/s

# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
h = logging.StreamHandler()
h.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
logger.addHandler(h)

# ---------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------
DEFAULT_SETTINGS = {
    "use_embedded_tor": True,
    "external_tor_path": "",
    "upload_limit_bps": DEFAULT_UPLOAD_LIMIT,
    "start_with_windows": False
}

if os.path.exists(SETTINGS_FILE):
    try:
        SETTINGS = json.loads(open(SETTINGS_FILE).read())
        for k, v in DEFAULT_SETTINGS.items():
            SETTINGS.setdefault(k, v)
    except:
        SETTINGS = DEFAULT_SETTINGS.copy()
else:
    SETTINGS = DEFAULT_SETTINGS.copy()


def save_settings():
    with open(SETTINGS_FILE, "w") as f:
        json.dump(SETTINGS, f, indent=2)
    refresh_upload_bucket(SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT))

# ---------------------------------------------------------
# START WITH WINDOWS (REGISTRY)
# ---------------------------------------------------------
def set_start_with_windows(enabled: bool):
    """Adds/removes registry entry HKCU\...\Run"""
    if sys.platform != "win32":
        return

    import winreg

    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    exe_path = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)

    try:
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS)

        if enabled:
            winreg.SetValueEx(reg, APP_NAME, 0, winreg.REG_SZ, exe_path)
        else:
            try:
                winreg.DeleteValue(reg, APP_NAME)
            except FileNotFoundError:
                pass

        winreg.CloseKey(reg)
    except Exception as e:
        logger.error(f"Registry error: {e}")

# ---------------------------------------------------------
# PATH SAFETY
# ---------------------------------------------------------
def safe_path(base, target):
    try:
        b = Path(base).resolve()
        t = Path(target).resolve()
        return b == t or b in t.parents
    except:
        return False

# ---------------------------------------------------------
# AV SCAN
# ---------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(8192), b""):
            h.update(c)
    return h.hexdigest()


try:
    SCAN_CACHE = json.loads(open(SCAN_CACHE_FILE).read())
except:
    SCAN_CACHE = {}


def save_scan_cache():
    with open(SCAN_CACHE_FILE, "w") as f:
        json.dump(SCAN_CACHE, f)


DEFENDER = os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe")


def scan_file(path):
    sha = sha256_file(path)
    now = time.time()

    cached = SCAN_CACHE.get(sha)
    if cached and now - cached["ts"] < 24 * 3600:
        return cached["clean"], cached["reason"]

    clean = False
    reason = "no_scanner"

    # Windows Defender
    if sys.platform == "win32" and os.path.exists(DEFENDER):
        try:
            r = subprocess.run(
                [DEFENDER, "-Scan", "-ScanType", "3", "-File", path],
                timeout=60, capture_output=True
            )
            if r.returncode == 0:
                clean, reason = True, "clean"
            else:
                reason = f"defender:{r.returncode}"
        except:
            reason = "defender_exception"

    else:
        # Linux/macOS with ClamAV
        for exe in ("clamdscan", "clamscan"):
            if shutil.which(exe):
                try:
                    r = subprocess.run([exe, "--no-summary", path],
                                       timeout=60, capture_output=True)
                    if r.returncode == 0:
                        clean, reason = True, "clean"
                    elif r.returncode == 1:
                        clean, reason = False, "infected"
                    else:
                        reason = "clam_error"
                except:
                    reason = "clam_exception"

    SCAN_CACHE[sha] = {"clean": clean, "reason": reason, "ts": now}
    save_scan_cache()

    return clean, reason

# ---------------------------------------------------------
# TOKEN BUCKET
# ---------------------------------------------------------
class TokenBucket:
    def __init__(self, cap, rate):
        self.cap = float(cap)
        self.tokens = float(cap)
        self.rate = float(rate)
        self.ts = time.monotonic()

    def refill(self):
        now = time.monotonic()
        dt = now - self.ts
        if dt > 0:
            self.tokens = min(self.cap, self.tokens + dt * self.rate)
            self.ts = now

    def consume(self, n):
        if self.rate <= 0:
            return
        need = float(n)
        while True:
            self.refill()
            if self.tokens >= need:
                self.tokens -= need
                return
            time.sleep(0.01)


UPLOAD_BUCKET = TokenBucket(DEFAULT_UPLOAD_LIMIT * 2, DEFAULT_UPLOAD_LIMIT)


def refresh_upload_bucket(limit_bps: int):
    """Recreate the global upload bucket when the user changes the limit."""
    global UPLOAD_BUCKET
    safe_limit = max(0, int(limit_bps)) or DEFAULT_UPLOAD_LIMIT
    UPLOAD_BUCKET = TokenBucket(safe_limit * 2, safe_limit)


# initialize upload bucket with persisted value
refresh_upload_bucket(SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT))

# ---------------------------------------------------------
# TOR (embedded or external)
# ---------------------------------------------------------
def find_embedded_tor():
    base = Path(__file__).parent / "tor"
    exe = base / ("tor.exe" if sys.platform == "win32" else "tor")
    if exe.exists():
        return str(exe)
    return None


def tor_cmd():
    if SETTINGS["use_embedded_tor"]:
        t = find_embedded_tor()
    else:
        t = SETTINGS.get("external_tor_path", "")
    return t if t and os.path.exists(t) else None


class TorThread(QThread):
    status = pyqtSignal(str)
    onion_ready = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.proc = None
        self.onion = None

    def run(self):
        tor = tor_cmd()
        if not tor:
            self.status.emit("Tor not found.")
            return

        self.status.emit("Starting Tor…")
        args = [
            tor, "--SocksPort", str(SOCKS_PORT),
            "--ControlPort", str(CTRL_PORT),
            "--DataDirectory", TOR_DATA_DIR
        ]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # wait port
        for _ in range(40):
            try:
                s = socket.create_connection(("127.0.0.1", CTRL_PORT), timeout=2)
                s.close()
                break
            except:
                time.sleep(1)

        try:
            sock = socket.create_connection(("127.0.0.1", CTRL_PORT))
            sock.sendall(b'AUTHENTICATE ""\r\n')
            if b"250" not in sock.recv(4096):
                self.status.emit("Tor authentication failed")
                return
        except:
            self.status.emit("ControlPort unreachable")
            return

        # ADD_ONION
        if os.path.exists(ONION_KEY_FILE):
            key = open(ONION_KEY_FILE).read().strip()
            cmd = f"ADD_ONION {key} Port=80,{FLASK_PORT}\r\n"
        else:
            cmd = f"ADD_ONION NEW:ED25519-V3 Port=80,{FLASK_PORT}\r\n"

        sock.sendall(cmd.encode())
        out = sock.recv(4096).decode()

        sid = None
        pkey = None

        for line in out.splitlines():
            if "ServiceID=" in line:
                sid = line.split("=")[1].strip()
            if "PrivateKey=" in line:
                pkey = line.split("=")[1].strip()

        if pkey:
            open(ONION_KEY_FILE, "w").write(pkey)

        if not sid:
            self.status.emit("Failed to create onion")
            return

        onion = f"http://{sid}.onion"
        self.onion = onion
        self.status.emit("Onion ready")
        self.onion_ready.emit(onion)


    def stop(self):
        if self.proc:
            self.proc.terminate()
            try: self.proc.wait(3)
            except: self.proc.kill()

TOR = TorThread()

# ---------------------------------------------------------
# SNAPSHOT SYSTEM
# ---------------------------------------------------------
_runtime_maps: Dict[str, Dict] = {}
MAP_TTL = 600

def cleanup_maps():
    now = time.time()
    for k in list(_runtime_maps.keys()):
        if now - _runtime_maps[k]["ts"] > MAP_TTL:
            _runtime_maps.pop(k, None)


def make_map(share_base):
    files = []
    vmap = {}

    for root, dirs, flist in os.walk(share_base):
        for f in flist:
            full = os.path.join(root, f)
            if not safe_path(share_base, full):
                continue

            rel = os.path.relpath(full, share_base).replace("\\", "/")
            st = os.stat(full)

            files.append({
                "path": rel,
                "size": st.st_size,
                "age_hours": int((time.time() - st.st_mtime)//3600)
            })
            vmap[rel] = full

    mid = secrets.token_hex(8)
    token = secrets.token_urlsafe(24)

    _runtime_maps[mid] = {"map": vmap, "token": token, "ts": time.time()}

    return mid, token, files

# ---------------------------------------------------------
# FLASK
# ---------------------------------------------------------
app = Flask(__name__)

def get_share_dir():
    if os.path.exists(SHARE_DIR_FILE):
        return open(SHARE_DIR_FILE).read().strip()
    return ""

@app.route("/list")
def list_files():
    cleanup_maps()
    base = get_share_dir()
    if not base:
        return jsonify({"error": "no_share_dir"}), 500

    mid, token, files = make_map(base)

    return jsonify({
        "map_id": mid,
        "map_token": token,
        "files": files
    })

@app.route("/download/<map_id>/<path:relp>")
def download(map_id, relp):
    cleanup_maps()
    entry = _runtime_maps.get(map_id)
    if not entry:
        return jsonify({"error": "bad_map"}), 404

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "no_token"}), 401

    if auth.split(" ", 1)[1] != entry["token"]:
        return jsonify({"error": "bad_token"}), 403

    real = entry["map"].get(relp)
    if not real or not os.path.exists(real):
        return jsonify({"error": "not_found"}), 404

    ok, reason = scan_file(real)
    if not ok:
        return jsonify({"error": "av_block", "reason": reason}), 403

    def stream():
        with open(real, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                UPLOAD_BUCKET.consume(len(chunk))
                yield chunk

    resp = Response(stream(), mimetype="application/octet-stream")
    resp.headers["Content-Disposition"] = f'attachment; filename="{os.path.basename(real)}"'
    return resp

# ---------------------------------------------------------
# SERVER THREAD
# ---------------------------------------------------------
class ServerThread(QThread):
    log = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def stop(self):
        self.running = False
        os._exit(0)

    def run(self):
        try:
            if serve:
                self.log.emit("Waitress serving…")
                serve(app, host="127.0.0.1", port=FLASK_PORT, threads=4)
            else:
                self.log.emit("Flask dev server running…")
                app.run(port=FLASK_PORT)
        except Exception as e:
            self.log.emit(f"Server error: {e}")

# ---------------------------------------------------------
# UI
# ---------------------------------------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nishizumi Sync Server Lite")
        self.resize(520, 560)
        self.server_running = False

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # STATUS
        self.status_lbl = QLabel("OFFLINE")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setStyleSheet("background:#8B0000; color:white; padding:8px;")
        layout.addWidget(self.status_lbl)

        # SHARE DIR
        layout.addWidget(QLabel("Folder to Share (root of setups):"))
        row = QHBoxLayout()
        self.share_edit = QLineEdit()
        btn = QPushButton("Select")
        btn.clicked.connect(self.pick_share)
        row.addWidget(self.share_edit)
        row.addWidget(btn)
        layout.addLayout(row)

        # TOR OPTIONS
        layout.addWidget(QLabel("Tor Options:"))
        self.chk_emb = QCheckBox("Use Embedded Tor")
        self.chk_ext = QCheckBox("Use External Tor")
        self.chk_emb.stateChanged.connect(self.sync_tor_opts)
        self.chk_ext.stateChanged.connect(self.sync_tor_opts)

        layout.addWidget(self.chk_emb)
        layout.addWidget(self.chk_ext)

        row2 = QHBoxLayout()
        self.tor_path_edit = QLineEdit()
        btn2 = QPushButton("Select tor.exe")
        btn2.clicked.connect(self.pick_tor)
        row2.addWidget(self.tor_path_edit)
        row2.addWidget(btn2)
        layout.addLayout(row2)

        # START WITH WINDOWS
        self.chk_start = QCheckBox("Start With Windows")
        self.chk_start.stateChanged.connect(self.toggle_start_with_windows)
        layout.addWidget(self.chk_start)

        # UPLOAD LIMIT
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Upload limit (KB/s):"))
        self.up_edit = QLineEdit(str(DEFAULT_UPLOAD_LIMIT//1024))
        row3.addWidget(self.up_edit)
        layout.addLayout(row3)

        # BUTTON START SERVER
        self.btn = QPushButton("START SERVER")
        self.btn.clicked.connect(self.toggle_server)
        layout.addWidget(self.btn)

        # ONION
        layout.addWidget(QLabel("Your Onion:"))
        self.onion_edit = QLineEdit()
        self.onion_edit.setReadOnly(True)
        layout.addWidget(self.onion_edit)

        # BUTTON REGENERATE ONION
        self.btn_regen = QPushButton("Regenerate Onion Identity (danger)")
        self.btn_regen.clicked.connect(self.regen_onion)
        layout.addWidget(self.btn_regen)

        # LOG & PROGRESS
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.log_txt = QTextEdit()
        self.log_txt.setReadOnly(True)
        layout.addWidget(self.log_txt)

        # LOAD SETTINGS
        self.load_settings()

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_txt.append(f"[{ts}] {msg}")
        logger.info(msg)

    def load_settings(self):
        if os.path.exists(SHARE_DIR_FILE):
            self.share_edit.setText(open(SHARE_DIR_FILE).read().strip())

        self.chk_emb.setChecked(SETTINGS["use_embedded_tor"])
        self.chk_ext.setChecked(not SETTINGS["use_embedded_tor"])
        self.tor_path_edit.setText(SETTINGS["external_tor_path"])

        self.chk_start.setChecked(SETTINGS["start_with_windows"])
        self.up_edit.setText(str(SETTINGS["upload_limit_bps"]//1024))

    def save_settings(self):
        SETTINGS["use_embedded_tor"] = self.chk_emb.isChecked()
        SETTINGS["external_tor_path"] = self.tor_path_edit.text().strip()
        try:
            SETTINGS["upload_limit_bps"] = int(self.up_edit.text().strip()) * 1024
        except:
            SETTINGS["upload_limit_bps"] = DEFAULT_UPLOAD_LIMIT
        save_settings()

    def pick_share(self):
        p = QFileDialog.getExistingDirectory(self, "Select share directory")
        if p:
            self.share_edit.setText(p)
            with open(SHARE_DIR_FILE, "w") as f:
                f.write(p)
            self.log("Share directory set.")

    def pick_tor(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select tor.exe", "", "Executables (*.exe)")
        if f:
            self.tor_path_edit.setText(f)
            self.log("External Tor path set.")

    def sync_tor_opts(self):
        sender = self.sender()
        if sender == self.chk_emb and self.chk_emb.isChecked():
            self.chk_ext.setChecked(False)
        elif sender == self.chk_ext and self.chk_ext.isChecked():
            self.chk_emb.setChecked(False)

    def toggle_start_with_windows(self):
        enabled = self.chk_start.isChecked()
        SETTINGS["start_with_windows"] = enabled
        save_settings()
        set_start_with_windows(enabled)
        self.log("Start with Windows: ON" if enabled else "OFF")

    def regen_onion(self):
        if os.path.exists(ONION_KEY_FILE):
            os.remove(ONION_KEY_FILE)
        QMessageBox.information(self, "Identity Reset", "Onion will change when server restarts.")
        self.log("Onion identity wiped.")

    def toggle_server(self):
        """Start or stop the server + Tor."""
        if not self.server_running:
            # START
            share = self.share_edit.text().strip()
            if not share or not os.path.exists(share):
                QMessageBox.warning(self, "Error", "Select a valid share directory.")
                return

            with open(SHARE_DIR_FILE, "w") as f:
                f.write(share)

            self.save_settings()

            # Tor
            TOR.status.connect(self.log)
            TOR.onion_ready.connect(self.set_onion)
            TOR.start()

            self.server_running = True
            self.btn.setText("STOP SERVER")
            self.status_lbl.setText("STARTING…")
            self.status_lbl.setStyleSheet("background:#FFA000; padding:8px;")

            # HTTP thread
            self.http = ServerThread()
            self.http.log.connect(self.log)
            self.http.start()

        else:
            # STOP
            TOR.stop()
            self.http.stop()
            self.server_running = False
            self.btn.setText("START SERVER")
            self.status_lbl.setText("OFFLINE")
            self.status_lbl.setStyleSheet("background:#8B0000; padding:8px;")
            self.log("Server stopped.")

    def set_onion(self, o):
        self.onion_edit.setText(o)
        self.status_lbl.setText("ONLINE")
        self.status_lbl.setStyleSheet("background:#006400; color:white; padding:8px;")
        self.log(f"Onion: {o}")

# ---------------------------------------------------------
# main
# ---------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

