#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nishizumi Share — Secure v2.2.1
=====================================
Quick start:
 - Requirements: Python 3.10+, pip install Flask PyQt6 requests waitress
 - Save as: nishizumi_share_v2_2_1.py
 - Run: python nishizumi_share_v2_2_1.py
 - Configure tor.exe path in System tab or write it in settings.json
 - Start server with the "START SERVER" button (System tab)
 - Configure outgoing share folder (Engineer) and incoming save folder (Client)
 - Use "Generate Token" (Engineer) to create a one-time token to share with someone
 - Use "START SYNC" (Client) to begin continuous synchronization
 - Monitor logs in the System tab for operational details
"""

# ------------------------------------------------------------------------------ 
# MIT License
# ------------------------------------------------------------------------------ 
# Copyright (c) 2025
# Maho Nishizumi
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction...
# (see full MIT in repository LICENSE)
# ------------------------------------------------------------------------------

# -------------------------
# Imports
# -------------------------
import os
import sys
import time
import json
import hmac
import shutil
import socket
import secrets
import hashlib
import subprocess
import logging
from pathlib import Path
from functools import wraps
from typing import Dict, Optional
from urllib.parse import quote

from flask import Flask, request, jsonify, Response

# Use waitress as production WSGI server
try:
    from waitress import serve
except Exception:
    serve = None  # will be checked before use

# PyQt6 (UI)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QMessageBox, QTextEdit, QPlainTextEdit, QHBoxLayout,
    QProgressBar, QCheckBox, QTabWidget, QGroupBox, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import pyqtSignal, QThread, QObject, Qt

# requests imported inside worker threads where needed to avoid import-time failure.

# -------------------------
# CONFIG & CONSTANTS
# -------------------------
APP_NAME = "NishizumiShare"
if sys.platform == "win32":
    CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
else:
    CONFIG_DIR = os.path.join(os.path.expanduser("~"), "." + APP_NAME)
os.makedirs(CONFIG_DIR, exist_ok=True)

# Persistent files inside CONFIG_DIR
KEY_FILE = os.path.join(CONFIG_DIR, "onion_private_key")
KEY_FILE_BAK = KEY_FILE + ".bak"
PEERS_FILE = os.path.join(CONFIG_DIR, "team_peers.txt")
RULES_FILE = os.path.join(CONFIG_DIR, "security_rules.txt")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
TOR_DATA_DIR = os.path.join(CONFIG_DIR, "tor_data")
SCAN_CACHE_FILE = os.path.join(CONFIG_DIR, "scan_cache.json")
ADMIN_KEY_FILE = os.path.join(CONFIG_DIR, "admin_key")  # HMAC key for fake names

os.makedirs(TOR_DATA_DIR, exist_ok=True)

# Network / ports
FLASK_PORT = 5000
SOCKS_PORT = 9050
CTRL_PORT = 9051
CTRL_HOST = "127.0.0.1"

# Defaults (override via UI/settings.json)
DEFAULT_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # per-file cap (200 MB)
DEFAULT_DOWNLOAD_LIMIT_BPS = 2 * 1024 * 1024    # 2 MB/s
DEFAULT_UPLOAD_LIMIT_BPS = 2 * 1024 * 1024      # 2 MB/s
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_REQUESTS = 60
EPHEMERAL_TTL = 600  # seconds for ephemeral /list maps
ONE_TIME_TOKEN_TTL_DEFAULT = 3600  # default one-time token validity (1 hour)

# Microsoft Defender path (Windows)
DEFENDER_PATH = os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe")

# Force AV scan default (UI toggle can override)
FORCE_AV_SCAN_DEFAULT = True

# Logging
logger = logging.getLogger("nishizumi_secure")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(ch)

# Flask app instance
app = Flask(__name__)

# Runtime global state
SWARM_FOLDER: str = ""            # outgoing folder selected in Engineer tab
SECURITY_ALERT_MODE: bool = False
FILES_SERVED_COUNT: int = 0

# -------------------------
# Settings persistence
# -------------------------
DEFAULT_SETTINGS = {
    "tor_path": "",
    "download_limit_bps": DEFAULT_DOWNLOAD_LIMIT_BPS,
    "upload_limit_bps": DEFAULT_UPLOAD_LIMIT_BPS,
    "max_file_size": DEFAULT_MAX_DOWNLOAD_BYTES,
    "force_av_scan": FORCE_AV_SCAN_DEFAULT,
    "peers": [],
    "share_dir": "",
    "save_dir": "",
    "sync_mode": 3,
    "team_folder": "Team_Setups"
}

if os.path.exists(SETTINGS_FILE):
    try:
        SETTINGS = json.loads(open(SETTINGS_FILE, "r", encoding="utf-8").read() or "{}")
        # ensure keys exist
        for k, v in DEFAULT_SETTINGS.items():
            if k not in SETTINGS:
                SETTINGS[k] = v
    except Exception:
        SETTINGS = DEFAULT_SETTINGS.copy()
else:
    SETTINGS = DEFAULT_SETTINGS.copy()
    try:
        open(SETTINGS_FILE, "w", encoding="utf-8").write(json.dumps(SETTINGS))
    except Exception:
        pass

def save_settings():
    """Persist SETTINGS to disk."""
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f, indent=2)
        try:
            os.chmod(SETTINGS_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        logger.exception("Failed to save settings")

# -------------------------
# ADMIN HMAC key (for deterministic fake names)
# -------------------------
if os.path.exists(ADMIN_KEY_FILE):
    try:
        ADMIN_KEY = open(ADMIN_KEY_FILE, "r", encoding="utf-8").read().strip()
    except Exception:
        ADMIN_KEY = secrets.token_urlsafe(48)
        try:
            with open(ADMIN_KEY_FILE, "w", encoding="utf-8") as f:
                f.write(ADMIN_KEY)
            os.chmod(ADMIN_KEY_FILE, 0o600)
        except Exception:
            pass
else:
    ADMIN_KEY = secrets.token_urlsafe(48)
    try:
        with open(ADMIN_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(ADMIN_KEY)
        try: os.chmod(ADMIN_KEY_FILE, 0o600)
        except: pass
    except Exception:
        pass
ADMIN_KEY_BYTES = ADMIN_KEY.encode()

# -------------------------
# Utilities (IO safety, hashing, path checks)
# -------------------------
def safe_write_file(path: str, data: str, make_backup: bool = True):
    """Atomically write `data` to `path`. Optionally make a .bak copy first."""
    try:
        if make_backup and os.path.exists(path):
            try: shutil.copyfile(path, path + ".bak")
            except: pass
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        try: os.chmod(path, 0o600)
        except: pass
        return True
    except Exception:
        logger.exception("safe_write_file")
        return False

def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_json(path: str, obj):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        try: os.chmod(path, 0o600)
        except: pass
        return True
    except Exception:
        logger.exception("save_json")
        return False

def sha256_of_file(path: str) -> str:
    """Return SHA256 hex digest of a file (streamed)."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def is_within_directory(base_dir: str, target_path: str) -> bool:
    """Ensure target_path is inside base_dir (mitigate directory traversal)."""
    try:
        base = Path(base_dir).resolve()
        target = Path(target_path).resolve()
        return base == target or base in target.parents
    except Exception:
        return False

def mask_name(n: str) -> str:
    """Return a masked version of filename for logs/UI to avoid leaking full names."""
    if len(n) <= 8:
        return "****" + n[-2:]
    return n[:3] + "..." + n[-3:]

# -------------------------
# DLP Manager: sanitize + deterministic fake names
# -------------------------
class DataProtectionManager:
    def __init__(self):
        self.rules = {}
        self.virtual_map = {}
        self.load_rules()

    def load_rules(self):
        """Read RULES_FILE lines like private=PUBLIC and build mapping."""
        self.rules = {}
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        if "=" in line and not line.strip().startswith("#"):
                            k, v = line.strip().split("=", 1)
                            self.rules[k.lower()] = v
            except Exception:
                logger.exception("DLP load_rules failed")

    def sanitize_component(self, comp: str) -> str:
        """Sanitize a path component (strip control chars, replace dangerous tokens)."""
        import unicodedata, re
        p = unicodedata.normalize("NFKC", comp)
        p = re.sub(r'[\x00-\x1f<>:"|?*\']', "_", p)
        p = p.replace("..", "_")
        lower = p.lower()
        for private_term, public_code in self.rules.items():
            if private_term in lower:
                idx = lower.find(private_term)
                p = p[:idx] + public_code + p[idx+len(private_term):]
                lower = p.lower()
        return p[:200]

    def make_fake_name(self, rel_path: str, key: bytes) -> str:
        """
        Create deterministic fake name for rel_path: sanitized path + short HMAC.
        This allows map lookup while avoiding leaking raw internal strings.
        """
        parts = rel_path.replace("\\", "/").split("/")
        sanitized = "/".join(self.sanitize_component(p) for p in parts)
        h = hmac.new(key, rel_path.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
        return f"{sanitized}__{h}"

dlp_manager = DataProtectionManager()

# -------------------------
# AV scan cache + scanning wrapper
# -------------------------
def load_scan_cache():
    if os.path.exists(SCAN_CACHE_FILE):
        try:
            return json.loads(open(SCAN_CACHE_FILE, "r", encoding="utf-8").read() or "{}")
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

def scan_with_windows_defender(path: str, timeout: int = 60):
    """Scan a file with Microsoft Defender's MpCmdRun.exe. Returns (bool, reason)."""
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
    """Attempt to scan with clamdscan or clamscan if available."""
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
    """
    High-level AV wrapper:
      - Use cached result if SHA256 is cached within 24h
      - Try Defender (Windows) then ClamAV
      - Cache result and return (clean_bool, reason)
      - If force_scan=True and no scanner available -> return (False, reason)
    """
    try:
        sha = sha256_of_file(path)
    except Exception as e:
        return False, f"hash_error:{str(e)[:200]}"
    now = int(time.time())
    cached = _scan_cache.get(sha)
    if cached and (now - cached.get("ts", 0) < 24 * 3600):
        return cached.get("clean", False), cached.get("reason", "cached")
    if sys.platform == "win32":
        ok, reason = scan_with_windows_defender(path, timeout=60)
    else:
        ok, reason = scan_with_clamav(path, timeout=120)
    _scan_cache[sha] = {"clean": ok, "reason": reason, "ts": now}
    save_scan_cache(_scan_cache)
    if not ok and force_scan:
        return False, reason
    return ok, reason

# -------------------------
# Ephemeral maps & one-time tokens (in-memory)
# -------------------------
_EPHEMERAL_MAPS: Dict[str, Dict] = {}
_ONE_TIME_TOKENS: Dict[str, Dict] = {}

def cleanup_ephemeral_maps():
    now = time.time()
    for k in list(_EPHEMERAL_MAPS.keys()):
        if now - _EPHEMERAL_MAPS[k].get("ts", 0) > EPHEMERAL_TTL:
            _EPHEMERAL_MAPS.pop(k, None)

def cleanup_one_time_tokens():
    now = time.time()
    for t in list(_ONE_TIME_TOKENS.keys()):
        if now > _ONE_TIME_TOKENS[t].get("expires", 0):
            _ONE_TIME_TOKENS.pop(t, None)

# -------------------------
# Rate limiting: GLOBAL bucket (Tor Hidden Service environment)
# -------------------------
_rate_store: Dict[str, Dict] = {}

def rate_limited(f):
    """
    Global rate limiter (not per-IP) because in onion services remote_addr == localhost.
    We keep a global timestamp list and limit the total request rate.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        global_request_bucket = _rate_store.setdefault("global", {"timestamps": []})
        now = time.time()
        # purge old timestamps
        global_request_bucket["timestamps"] = [t for t in global_request_bucket["timestamps"] if now - t < RATE_LIMIT_WINDOW]
        # allow a larger global cap (rate-limited but permissive)
        if len(global_request_bucket["timestamps"]) >= (RATE_LIMIT_REQUESTS * 10):
            return jsonify({"error": "global_rate_limit_exceeded"}), 429
        global_request_bucket["timestamps"].append(now)
        return f(*args, **kwargs)
    return wrapped

def require_map_or_token(f):
    """
    Allow access with either:
      - the map_token issued in /list for a map_id, OR
      - a one-time UI token stored in _ONE_TIME_TOKENS.
    Authorization header must be: 'Bearer <token>'
    """
    @wraps(f)
    def wrapped(map_id, *args, **kwargs):
        cleanup_ephemeral_maps()
        cleanup_one_time_tokens()
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        token = auth.split(" ", 1)[1]
        entry = _EPHEMERAL_MAPS.get(map_id)
        if entry and hmac.compare_digest(token, entry.get("token", "")):
            return f(map_id, *args, **kwargs)
        ot = _ONE_TIME_TOKENS.get(token)
        if ot and time.time() < ot.get("expires", 0):
            bound_map = ot.get("map_id")
            if bound_map and bound_map != map_id:
                return jsonify({"error": "token_not_for_map"}), 403
            return f(map_id, *args, **kwargs)
        return jsonify({"error": "invalid_or_expired_token"}), 401
    return wrapped

# -------------------------
# TokenBucket implementation (smooth throttling)
# -------------------------
class TokenBucket:
    def __init__(self, capacity_bytes: int, fill_rate_bps: float):
        """
        capacity_bytes: maximum tokens (burst allowance)
        fill_rate_bps: tokens added per second
        """
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
        """Block until num_bytes are available, then deduct them from bucket."""
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

# Global upload bucket for outgoing streaming
GLOBAL_UPLOAD_BUCKET: Optional[TokenBucket] = None

def ensure_global_upload_bucket():
    global GLOBAL_UPLOAD_BUCKET
    ul = SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT_BPS) or DEFAULT_UPLOAD_LIMIT_BPS
    capacity = int(ul * 2)  # allow 2-second burst
    GLOBAL_UPLOAD_BUCKET = TokenBucket(capacity, float(ul))

# -------------------------
# Flask endpoints: /list and /download
# -------------------------
@app.route("/list", methods=["GET"])
@rate_limited
def list_files():
    """
    Return an ephemeral snapshot of shared files (fake names) plus a map_token.
    Clients should call /download/<map_id>/<fake_name> with Authorization: Bearer <token>.
    """
    cleanup_ephemeral_maps()
    global SWARM_FOLDER
    if not SWARM_FOLDER or not os.path.exists(SWARM_FOLDER):
        return jsonify({"error": "node_not_ready"}), 404

    dlp_manager.load_rules()
    files_data = []
    virtual_map = {}
    try:
        for root, dirs, files in os.walk(SWARM_FOLDER):
            for file in files:
                full_path = os.path.join(root, file)
                if not is_within_directory(SWARM_FOLDER, full_path):
                    logger.info("Skipping file outside swarm folder: %s", mask_name(file))
                    continue
                rel_path = os.path.relpath(full_path, SWARM_FOLDER).replace("\\", "/")
                fake = dlp_manager.make_fake_name(rel_path, ADMIN_KEY_BYTES)
                try:
                    stat = os.stat(full_path)
                    age_hours = int((time.time() - stat.st_mtime) // 3600)
                    size = stat.st_size
                except Exception:
                    age_hours = -1; size = -1
                files_data.append({"path": fake, "size": size, "age_hours": age_hours})
                virtual_map[fake] = full_path
        map_json = json.dumps(files_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        sig = hmac.new(ADMIN_KEY_BYTES, map_json, hashlib.sha256).hexdigest()
        map_id = secrets.token_hex(8)
        map_token = secrets.token_urlsafe(24)
        _EPHEMERAL_MAPS[map_id] = {"map": virtual_map, "sig": sig, "token": map_token, "ts": time.time()}
        return jsonify({
            "root": "Repository",
            "files": files_data,
            "map_id": map_id,
            "map_sig": sig,
            "map_token": map_token,
            "security_alert": bool(SECURITY_ALERT_MODE)
        })
    except Exception:
        logger.exception("list failed")
        return jsonify({"error": "internal_error"}), 500

def stream_file_with_bucket(path: str, upload_bucket: Optional[TokenBucket], chunk_size: int = 64 * 1024):
    """Generator that streams file chunks while consuming tokens from upload_bucket."""
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            if upload_bucket:
                upload_bucket.consume(len(data))
            yield data

@app.route("/download/<map_id>/<path:fake_name>", methods=["GET"])
@rate_limited
@require_map_or_token
def download_file(map_id, fake_name):
    """
    Serve the real file corresponding to fake_name inside ephemeral map map_id.
    Requires Authorization: Bearer <token>.
    File is AV-scanned before serving when enabled.
    Streaming is throttled by GLOBAL_UPLOAD_BUCKET (upload limit).
    """
    entry = _EPHEMERAL_MAPS.get(map_id)
    if not entry:
        return jsonify({"error": "map_not_found"}), 404
    virtual_map = entry.get("map", {})
    real_path = virtual_map.get(fake_name)
    if not real_path or not os.path.exists(real_path):
        return jsonify({"error": "file_not_found"}), 404
    if not is_within_directory(SWARM_FOLDER, real_path):
        return jsonify({"error": "forbidden"}), 403

    force_scan = SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT)
    scan_ok, reason = av_scan_file(real_path, force_scan=force_scan)
    if not scan_ok:
        logger.info("Blocked outgoing file by AV: %s reason=%s", mask_name(os.path.basename(real_path)), reason)
        return jsonify({"error": "file_blocked_by_av", "reason": reason}), 403

    global FILES_SERVED_COUNT
    FILES_SERVED_COUNT += 1

    ensure_global_upload_bucket()
    response = Response(stream_file_with_bucket(real_path, GLOBAL_UPLOAD_BUCKET), mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = f'attachment; filename="{os.path.basename(real_path)}"'
    return response

# -------------------------
# Tor ControlPort helpers & TorManagerWorker
# -------------------------
def _send_cmd(sock: socket.socket, cmd: str):
    """Send command to Tor control port and collect reply lines (tolerant parser)."""
    if not cmd.endswith("\r\n"):
        cmd = cmd + "\r\n"
    try:
        sock.sendall(cmd.encode("utf-8"))
    except Exception:
        logger.exception("_send_cmd send failed")
        return []
    sock.settimeout(5.0)
    data = b""; lines = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n" in data:
                parts = data.split(b"\r\n")
                for p in parts[:-1]:
                    if p:
                        try:
                            lines.append(p.decode("utf-8", errors="ignore"))
                        except:
                            lines.append(str(p))
                if lines and (lines[-1].startswith("250 ") or lines[-1].startswith("550 ")):
                    return lines
    except Exception:
        pass
    return lines

def _try_auth_cookie(sock: socket.socket, tor_data_dir: str):
    """Attempt cookie-based authentication using tor_data_dir/control_auth_cookie or fallback AUTHENTICATE ""."""
    try:
        cookie_path = os.path.join(tor_data_dir, "control_auth_cookie")
        if os.path.exists(cookie_path):
            with open(cookie_path, "rb") as f:
                cookie_hex = f.read().hex()
            lines = _send_cmd(sock, "AUTHENTICATE " + cookie_hex)
            if any(l.startswith("250") for l in lines):
                return True
    except Exception:
        logger.exception("cookie auth failed")
    try:
        lines = _send_cmd(sock, 'AUTHENTICATE ""')
        if any(l.startswith("250") for l in lines):
            return True
    except Exception:
        pass
    return False

def _try_auth_password(sock: socket.socket, password: str):
    """Try AUTHENTICATE with quoted password string."""
    try:
        cmd = 'AUTHENTICATE "{}"'.format(password.replace('"', '\\"'))
        lines = _send_cmd(sock, cmd)
        if any(l.startswith("250") for l in lines):
            return True
    except Exception:
        logger.exception("password auth failed")
    return False

class TorManagerWorker(QThread):
    """
    Starts a tor.exe process and configures an onion service via the ControlPort.
    On success, emits onion_ready(onion_url) and then runs the Flask app under Waitress
    inside this thread (blocking). Using Waitress provides production-grade serving.
    """
    status_update = pyqtSignal(str)
    onion_ready = pyqtSignal(str)
    identity_reset = pyqtSignal()

    def __init__(self, tor_exe_path: str):
        super().__init__()
        self.tor_exe_path = tor_exe_path
        self.control_password = None
        self.hashed_password = None

    def run(self):
        if not self.tor_exe_path or not os.path.exists(self.tor_exe_path):
            self.status_update.emit("Tor path missing or invalid")
            return
        tor_data_dir = TOR_DATA_DIR
        os.makedirs(tor_data_dir, exist_ok=True)
        self.status_update.emit("Preparing Tor (attempting hashed control password)...")

        pw = secrets.token_urlsafe(20)
        hashed = None
        try:
            res = subprocess.run([self.tor_exe_path, "--hash-password", pw], capture_output=True, text=True, timeout=10)
            out = (res.stdout or "") + (res.stderr or "")
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if lines:
                candidate = lines[-1]
                if len(candidate) > 8:
                    hashed = candidate
        except Exception:
            hashed = None

        args = [self.tor_exe_path, "--SocksPort", str(SOCKS_PORT), "--ControlPort", str(CTRL_PORT), "--DataDirectory", tor_data_dir]
        if hashed:
            args += ["--HashedControlPassword", hashed]
            self.control_password = pw
            self.hashed_password = hashed
            self.status_update.emit("Will start Tor with generated HashedControlPassword.")
        else:
            self.status_update.emit("Hashed password generation failed; will try cookie auth.")

        try:
            tor_proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        creationflags=0x08000000 if sys.platform == 'win32' else 0)
        except Exception as e:
            self.status_update.emit("Failed to start Tor: " + str(e))
            return

        sock = None
        for _ in range(15):
            try:
                sock = socket.create_connection((CTRL_HOST, CTRL_PORT), timeout=5)
                break
            except Exception:
                time.sleep(1)
        if not sock:
            self.status_update.emit("ControlPort not reachable")
            try: tor_proc.kill()
            except: pass
            return

        authenticated = False
        if self.control_password:
            if _try_auth_password(sock, self.control_password):
                authenticated = True
            else:
                self.status_update.emit("Password auth failed; attempting cookie auth")
        if not authenticated:
            if _try_auth_cookie(sock, tor_data_dir):
                authenticated = True

        if not authenticated:
            self.status_update.emit("Could not authenticate to Tor ControlPort")
            try: tor_proc.kill()
            except: pass
            return

        # ADD_ONION phase: restore existing key if present; otherwise create a new one
        service_id = None; private_key = None
        try:
            if os.path.exists(KEY_FILE):
                try:
                    with open(KEY_FILE, "r", encoding="utf-8") as f:
                        key_data = f.read().strip()
                    if ":" in key_data:
                        k_type, k_blob = key_data.split(":", 1)
                    else:
                        k_type, k_blob = ("ED25519-V3", key_data)
                    resp = _send_cmd(sock, f"ADD_ONION {k_type}:{k_blob} Port=80,{FLASK_PORT}")
                    for l in resp:
                        if "ServiceID=" in l: service_id = l.split("ServiceID=", 1)[1].strip()
                        if "PrivateKey=" in l: private_key = l.split("PrivateKey=", 1)[1].strip()
                except Exception:
                    logger.exception("Restoring existing key failed")
            if not service_id:
                resp = _send_cmd(sock, f"ADD_ONION NEW:ED25519-V3 Port=80,{FLASK_PORT}")
                for l in resp:
                    if "ServiceID=" in l: service_id = l.split("ServiceID=", 1)[1].strip()
                    if "PrivateKey=" in l: private_key = l.split("PrivateKey=", 1)[1].strip()
                if private_key:
                    safe_write_file(KEY_FILE, private_key, make_backup=False)
                    try: os.chmod(KEY_FILE, 0o600)
                    except: pass
        except Exception:
            logger.exception("ADD_ONION phase failed")

        onion = f"http://{service_id}.onion" if service_id else "unknown"
        self.onion_ready.emit(onion)
        self.status_update.emit(f"Service Ready: {onion}")

        # Run Flask app with Waitress (production WSGI) inside this thread (blocks)
        try:
            if serve is None:
                # fallback to development server if waitress not installed (warn)
                self.status_update.emit("Waitress not available, running Flask dev server (not recommended).")
                app.run(port=FLASK_PORT, use_reloader=False, threaded=True)
            else:
                # threads=4 is a reasonable default; change via SETTINGS if you need.
                serve(app, host="127.0.0.1", port=FLASK_PORT, threads=4)
        except Exception:
            logger.exception("Waitress serve failed")

# -------------------------
# SwarmSyncWorker (client downloading)
# -------------------------
class SwarmSyncWorker(QThread):
    log = pyqtSignal(str)
    finished_cycle = pyqtSignal(str)
    security_warning = pyqtSignal(str)
    progress_update = pyqtSignal(int, str)

    def __init__(self, peers_list, save_dir, team_name, sync_mode, only_sto, scan_virus):
        super().__init__()
        self.peers = [p.strip() for p in peers_list if p.strip()]
        self.save_dir = save_dir
        self.team_name = team_name
        self.sync_mode = sync_mode
        self.only_sto = only_sto
        self.scan_virus = scan_virus
        self.running = True

    def stop(self): self.running = False

    def is_safe_path(self, base, path):
        try:
            base = os.path.abspath(base); path = os.path.abspath(path)
            return os.path.commonpath([base, path]) == base
        except Exception:
            return False

    def write_log(self, msg: str):
        self.log.emit(msg)

    def run(self):
        """Continuous sync loop."""
        import requests
        download_limit = SETTINGS.get("download_limit_bps", DEFAULT_DOWNLOAD_LIMIT_BPS) or DEFAULT_DOWNLOAD_LIMIT_BPS
        dl_bucket = TokenBucket(int(download_limit * 2), float(download_limit))
        chunk_size = 64 * 1024
        proxies = {'http': f'socks5h://127.0.0.1:{SOCKS_PORT}', 'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'}
        while self.running:
            self.write_log("--- Sync cycle start ---")
            total_new = 0
            for peer in self.peers:
                if not self.running: break
                if not peer.endswith(".onion"): continue
                peer_url = peer if peer.startswith("http") else f"http://{peer}"
                try:
                    r = requests.get(f"{peer_url}/list", proxies=proxies, timeout=30)
                    if r.status_code != 200:
                        continue
                    data = r.json()
                    if data.get("security_alert"):
                        self.security_warning.emit(f"Peer {peer} reports security alert!")
                    map_id = data.get("map_id"); map_token = data.get("map_token")
                    if not map_id or not map_token:
                        continue
                    remote_files = data.get("files", [])
                    for rf in remote_files:
                        if not self.running: break
                        rel_path = rf.get("path")
                        if self.only_sto and not rel_path.lower().endswith(".sto"): continue
                        clean_rel_path = rel_path.replace("\\", "/")
                        # Map to local path depending on sync_mode
                        if self.sync_mode == 3:
                            parts = clean_rel_path.split("/")
                            if len(parts) > 1:
                                car = parts[0]; rest = "/".join(parts[1:])
                                final_rel = os.path.join(car, self.team_name, rest)
                            else:
                                final_rel = os.path.join("_General", self.team_name, parts[0])
                        elif self.sync_mode == 2:
                            final_rel = os.path.join(self.team_name, clean_rel_path)
                        else:
                            final_rel = clean_rel_path
                        local_path = os.path.join(self.save_dir, final_rel)
                        should_download = False
                        if not os.path.exists(local_path):
                            should_download = True
                        else:
                            s = os.stat(local_path)
                            if rf.get("age_hours", 0) >= 0 and rf.get("size", -1) != s.st_size:
                                should_download = True
                        if not should_download: continue
                        if not self.is_safe_path(self.save_dir, local_path): continue
                        fname = os.path.basename(local_path)
                        size = rf.get("size", 0)
                        if size and size > SETTINGS.get("max_file_size", DEFAULT_MAX_DOWNLOAD_BYTES):
                            self.write_log(f"Skipping large file {fname}")
                            continue
                        tmp_dir = os.path.join(self.save_dir, ".quarantine")
                        os.makedirs(tmp_dir, exist_ok=True)
                        tmp_path = os.path.join(tmp_dir, secrets.token_hex(8) + "_" + fname)
                        headers = {"Authorization": f"Bearer {map_token}"}
                        try:
                            with requests.get(f"{peer_url}/download/{quote(map_id)}/{quote(rel_path, safe='')}", proxies=proxies, stream=True, timeout=120, headers=headers) as fr:
                                if fr.status_code != 200:
                                    self.write_log(f"Failed to download {fname} from {peer}")
                                    continue
                                total_length = fr.headers.get("content-length")
                                dl = 0
                                with open(tmp_path, "wb") as outf:
                                    if total_length is None:
                                        for chunk in fr.iter_content(chunk_size=chunk_size):
                                            if not self.running: break
                                            dl_bucket.consume(len(chunk))
                                            outf.write(chunk)
                                    else:
                                        total_length = int(total_length)
                                        for chunk in fr.iter_content(chunk_size=chunk_size):
                                            if not self.running: break
                                            dl_bucket.consume(len(chunk))
                                            dl += len(chunk)
                                            outf.write(chunk)
                                            pct = int(100 * dl / (total_length or 1))
                                            self.progress_update.emit(pct, f"Downloading {fname}")
                                try: os.chmod(tmp_path, 0o600)
                                except: pass
                                scan_ok, reason = av_scan_file(tmp_path, force_scan=SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT))
                                if not scan_ok:
                                    try: os.remove(tmp_path)
                                    except: pass
                                    self.write_log(f"AV blocked {fname}: {reason}")
                                    continue
                                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                                os.replace(tmp_path, local_path)
                                os.utime(local_path, (time.time(), int(time.time())))
                                total_new += 1
                                self.progress_update.emit(100, f"Saved {fname}")
                        except Exception:
                            logger.exception("Download exception")
                            try:
                                if os.path.exists(tmp_path): os.remove(tmp_path)
                            except: pass
                except Exception:
                    logger.exception("Peer sync exception")
            self.finished_cycle.emit(f"Cycle finished. New: {total_new}")
            for _ in range(30):
                if not self.running: break
                time.sleep(1)

# -------------------------
# UI: Main window (Client / Engineer / System)
# -------------------------
class FlaskSignals(QObject):
    file_served = pyqtSignal(str)
flask_bridge = FlaskSignals()

class MainAppWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nishizumi Share — Secure v2.2.1")
        self.resize(960, 820)
        self.tor_worker = None
        self.sync_worker = None
        self.served_count = 0
        self.init_ui()
        self.load_settings()
        # Do not auto-start Tor here; user must press START SERVER in System tab.

    def init_ui(self):
        layout = QVBoxLayout(self)
        # set initial status to "not running" to reflect actual behavior
        self.lbl_global_status = QLabel("SERVER NOT RUNNING")
        self.lbl_global_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_global_status.setStyleSheet("background:#555; color:#fff; padding:8px; font-weight:bold; border-radius:6px;")
        layout.addWidget(self.lbl_global_status)

        self.tabs = QTabWidget()

        # CLIENT TAB
        tab_client = QWidget(); l_client = QVBoxLayout(tab_client)
        l_client.addWidget(QLabel("<b>1) Destination folder (where setups will be saved)</b>"))
        h1 = QHBoxLayout()
        self.btn_dest = QPushButton("📁 Select iRacing/setups folder"); self.btn_dest.clicked.connect(self.choose_dest)
        self.lbl_dest = QLineEdit(); self.lbl_dest.setReadOnly(True)
        h1.addWidget(self.btn_dest); h1.addWidget(self.lbl_dest)
        l_client.addLayout(h1)

        l_client.addWidget(QLabel("<b>2) Peers (one per line)</b>"))
        self.txt_peers = QPlainTextEdit(); self.txt_peers.setPlaceholderText("paste team .onion links here (one per line)")
        l_client.addWidget(self.txt_peers)

        gb = QGroupBox("Sync configuration")
        gb_layout = QVBoxLayout()
        self.rb_smart = QRadioButton("Smart Mode (create per-car folder)"); self.rb_smart.setChecked(True)
        self.rb_folder = QRadioButton("Simple Mirror (mirror as-is)")
        bg = QButtonGroup(self); bg.addButton(self.rb_smart, 3); bg.addButton(self.rb_folder, 2)
        gb_layout.addWidget(self.rb_smart); gb_layout.addWidget(self.rb_folder)
        team_row = QHBoxLayout()
        team_row.addWidget(QLabel("Team folder name:"))
        self.txt_team = QLineEdit("Team_Setups"); team_row.addWidget(self.txt_team)
        gb_layout.addLayout(team_row)
        self.lbl_preview = QLabel("Preview: iRacing/setups/[CAR]/Team_Setups/file.sto")
        gb_layout.addWidget(self.lbl_preview)
        gb.setLayout(gb_layout)
        l_client.addWidget(gb)

        expl = QTextEdit(); expl.setReadOnly(True); expl.setFixedHeight(110)
        expl.setHtml(
            "<b>Continuous synchronization</b><br>"
            "The client polls peers periodically (default: 30s). For each new/changed file the client will:"
            "<ol>"
            "<li>Download into <code>.quarantine</code></li>"
            "<li>AV-scan the file (Defender/ClamAV)</li>"
            "<li>If clean, move to the final destination (Smart Mode preserves per-car structure)</li>"
            "</ol>"
            "<i>Tip:</i> tune download/upload limits to avoid impacting your gameplay."
        )
        l_client.addWidget(expl)

        # speed controls
        speed_row = QHBoxLayout()
        speed_row.addWidget(QLabel("Download limit (KB/s):"))
        self.input_dl = QLineEdit(str(int(SETTINGS.get("download_limit_bps", DEFAULT_DOWNLOAD_LIMIT_BPS) // 1024)))
        speed_row.addWidget(self.input_dl)
        speed_row.addWidget(QLabel("Upload limit (KB/s):"))
        self.input_ul = QLineEdit(str(int(SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT_BPS) // 1024)))
        speed_row.addWidget(self.input_ul)
        l_client.addLayout(speed_row)

        # sync controls
        self.btn_sync = QPushButton("START SYNC"); self.btn_sync.clicked.connect(self.toggle_sync)
        l_client.addWidget(self.btn_sync)
        l_client.addStretch(1)
        self.tabs.addTab(tab_client, "Client")

        # ENGINEER TAB
        tab_server = QWidget(); l_server = QVBoxLayout(tab_server)
        l_server.addWidget(QLabel("<b>Share (outgoing folder)</b>"))
        h2 = QHBoxLayout()
        self.btn_orig = QPushButton("📁 Select outgoing folder"); self.btn_orig.clicked.connect(self.choose_origin)
        self.lbl_orig = QLineEdit(); self.lbl_orig.setReadOnly(True)
        h2.addWidget(self.btn_orig); h2.addWidget(self.lbl_orig)
        l_server.addLayout(h2)

        l_server.addWidget(QLabel("<b>Your .onion link</b>"))
        self.txt_my_link = QLineEdit(); self.txt_my_link.setReadOnly(True)
        l_server.addWidget(self.txt_my_link)

        l_server.addWidget(QLabel("<b>DLP rules (example: internal=PUBLIC)</b>"))
        self.txt_rules = QPlainTextEdit(); l_server.addWidget(self.txt_rules)
        btn_save_rules = QPushButton("Save rules"); btn_save_rules.clicked.connect(self.save_rules); l_server.addWidget(btn_save_rules)

        self.lbl_served = QLabel("Files served: 0"); l_server.addWidget(self.lbl_served)

        # Ephemeral token generator
        l_server.addWidget(QLabel("<b>Generate ephemeral token (one-off sharing)</b>"))
        token_row = QHBoxLayout()
        self.input_token_ttl = QLineEdit(str(ONE_TIME_TOKEN_TTL_DEFAULT // 60))  # minutes
        self.input_token_note = QLineEdit("One-off usage — send by DM")
        token_row.addWidget(QLabel("TTL (min):")); token_row.addWidget(self.input_token_ttl)
        token_row.addWidget(QLabel("Note:")); token_row.addWidget(self.input_token_note)
        l_server.addLayout(token_row)
        gen_row = QHBoxLayout()
        self.btn_gen_token = QPushButton("Generate token"); self.btn_gen_token.clicked.connect(self.generate_one_time_token)
        self.input_generated_token = QLineEdit(); self.input_generated_token.setReadOnly(True)
        self.btn_copy_token = QPushButton("Copy token"); self.btn_copy_token.clicked.connect(self.copy_generated_token)
        gen_row.addWidget(self.btn_gen_token); gen_row.addWidget(self.input_generated_token); gen_row.addWidget(self.btn_copy_token)
        l_server.addLayout(gen_row)
        l_server.addWidget(QLabel("<i>Token is temporary — share only with intended recipient. Token can be bound to the current snapshot.</i>"))
        self.tabs.addTab(tab_server, "Engineer")

        # SYSTEM TAB
        tab_sys = QWidget(); l_sys = QVBoxLayout(tab_sys)
        tor_row = QHBoxLayout()
        self.input_tor = QLineEdit(); self.input_tor.setPlaceholderText("Path to tor.exe (optional)")
        self.btn_locate_tor = QPushButton("Locate Tor"); self.btn_locate_tor.clicked.connect(self.locate_tor)
        self.btn_start_server = QPushButton("START SERVER"); self.btn_start_server.clicked.connect(self.toggle_server)
        tor_row.addWidget(self.input_tor); tor_row.addWidget(self.btn_locate_tor); tor_row.addWidget(self.btn_start_server)
        l_sys.addLayout(tor_row)

        av_row = QHBoxLayout()
        self.chk_force_av = QCheckBox("Force AV scan (block transfers if no scanner)"); self.chk_force_av.setChecked(SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT))
        av_row.addWidget(self.chk_force_av)
        self.btn_regen = QPushButton("REGENERATE IDENTITY"); self.btn_regen.clicked.connect(self.burn_identity)
        av_row.addWidget(self.btn_regen)
        l_sys.addLayout(av_row)

        l_sys.addWidget(QLabel("<b>Logs</b>"))
        self.txt_log = QTextEdit(); self.txt_log.setReadOnly(True); self.txt_log.setStyleSheet("background:#000; color:#0f0;")
        l_sys.addWidget(self.txt_log, stretch=1)
        self.tabs.addTab(tab_sys, "System")

        layout.addWidget(self.tabs)
        self.progress = QProgressBar(); self.progress.setValue(0); layout.addWidget(self.progress)
        flask_bridge.file_served.connect(self.on_file_served)

    # -------------------------
    # UI helpers
    # -------------------------
    def write_log(self, msg: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.txt_log.append(f"[{ts}] {msg}")
        except Exception:
            pass
        logger.info(msg)

    def on_file_served(self, name: str):
        self.served_count += 1
        self.lbl_served.setText(f"Files served: {self.served_count}")
        self.write_log(f"Served: {mask_name(name)}")

    def choose_dest(self):
        f = QFileDialog.getExistingDirectory(self, "Select iRacing/setups folder")
        if f:
            SETTINGS["save_dir"] = f
            save_settings()
            self.lbl_dest.setText(f)
            self.write_log(f"Destination folder set: {f}")

    def choose_origin(self):
        f = QFileDialog.getExistingDirectory(self, "Select outgoing folder")
        if f:
            global SWARM_FOLDER
            SWARM_FOLDER = f
            SETTINGS["share_dir"] = f
            save_settings()
            self.lbl_orig.setText(os.path.basename(f))
            self.write_log(f"Outgoing folder set: {f}")

    def locate_tor(self):
        f, _ = QFileDialog.getOpenFileName(self, "Locate tor.exe", "", "Executables (*.exe);;All Files (*)")
        if f:
            self.input_tor.setText(f)
            SETTINGS["tor_path"] = f
            save_settings()
            self.write_log("Tor path saved")

    def save_rules(self):
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                f.write(self.txt_rules.toPlainText())
            dlp_manager.load_rules()
            self.write_log("DLP rules saved")
        except Exception:
            self.write_log("Failed to save DLP rules")

    def load_settings(self):
        # load peers file
        if os.path.exists(PEERS_FILE):
            try:
                with open(PEERS_FILE, "r", encoding="utf-8") as f:
                    self.txt_peers.setPlainText(f.read())
            except Exception:
                pass
        # load DLP rules
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    self.txt_rules.setPlainText(f.read())
            except Exception:
                pass
        # apply stored settings
        try:
            torp = SETTINGS.get("tor_path", "")
            if torp: self.input_tor.setText(torp)
            dl = SETTINGS.get("download_limit_bps", DEFAULT_DOWNLOAD_LIMIT_BPS) // 1024
            ul = SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT_BPS) // 1024
            self.input_dl.setText(str(int(dl))); self.input_ul.setText(str(int(ul)))
            self.chk_force_av.setChecked(SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT))
            # restore share/save folders
            if SETTINGS.get("share_dir"):
                global SWARM_FOLDER
                SWARM_FOLDER = SETTINGS.get("share_dir"); self.lbl_orig.setText(os.path.basename(SWARM_FOLDER))
            if SETTINGS.get("save_dir"):
                self.lbl_dest.setText(SETTINGS.get("save_dir"))
            # restore sync mode and team folder
            if SETTINGS.get("team_folder"):
                self.txt_team.setText(SETTINGS.get("team_folder"))
            if SETTINGS.get("sync_mode") == 3:
                self.rb_smart.setChecked(True)
            else:
                self.rb_folder.setChecked(True)
        except Exception:
            pass

    def toggle_server(self):
        """Start Tor and the HTTP/Onion server via TorManagerWorker."""
        if self.tor_worker and self.tor_worker.isRunning():
            self.write_log("Server already running")
            return
        tor_path = self.input_tor.text().strip() or SETTINGS.get("tor_path", "")
        if not tor_path or not os.path.exists(tor_path):
            QMessageBox.critical(self, "Tor missing", "tor.exe not found. Please specify the path.")
            return
        SETTINGS["tor_path"] = tor_path; save_settings()
        self.tor_worker = TorManagerWorker(tor_path)
        self.tor_worker.status_update.connect(self.write_log)
        self.tor_worker.onion_ready.connect(self.on_onion_ready)
        self.tor_worker.identity_reset.connect(lambda: QMessageBox.warning(self, "Identity", "Identity regenerated"))
        # update status
        self.lbl_global_status.setText("STARTING TOR SERVER…")
        self.lbl_global_status.setStyleSheet("background:#FFA000; color:#000; padding:8px; font-weight:bold; border-radius:6px;")
        self.tor_worker.start()
        self.write_log("Starting server (Tor)...")

    def on_onion_ready(self, onion: str):
        self.txt_my_link.setText(onion)
        self.lbl_global_status.setText("ONLINE - TOR CONNECTED")
        self.lbl_global_status.setStyleSheet("background:#2E7D32; color:#fff; padding:8px; border-radius:6px;")
        self.write_log(f"Onion ready: {onion}")

    def toggle_sync(self):
        """Start/stop continuous client sync and persist UI speed settings."""
        if self.sync_worker and self.sync_worker.isRunning():
            self.sync_worker.stop()
            self.btn_sync.setText("START SYNC")
            self.write_log("Stopping continuous sync...")
            return
        try:
            dl_kb = max(0, int(self.input_dl.text().strip()))
            ul_kb = max(0, int(self.input_ul.text().strip()))
            SETTINGS["download_limit_bps"] = dl_kb * 1024
            SETTINGS["upload_limit_bps"] = ul_kb * 1024
            SETTINGS["force_av_scan"] = self.chk_force_av.isChecked()
            peers = [l.strip() for l in self.txt_peers.toPlainText().splitlines() if l.strip()]
            SETTINGS["peers"] = peers
            # save sync_mode and team_folder
            SETTINGS["sync_mode"] = 3 if self.rb_smart.isChecked() else 2
            SETTINGS["team_folder"] = self.txt_team.text().strip() or "Team_Setups"
            save_settings()
        except Exception:
            self.write_log("Error applying limits")
        try:
            with open(PEERS_FILE, "w", encoding="utf-8") as f:
                f.write(self.txt_peers.toPlainText())
        except Exception:
            pass
        dest = SETTINGS.get("save_dir") or self.lbl_dest.text().strip()
        if not dest:
            QMessageBox.warning(self, "Missing destination", "Please select a destination folder first.")
            return
        peers = SETTINGS.get("peers", [])
        self.sync_worker = SwarmSyncWorker(peers, dest, self.txt_team.text().strip() or "Team_Setups", 3 if self.rb_smart.isChecked() else 2, True, SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT))
        self.sync_worker.log.connect(self.write_log)
        self.sync_worker.finished_cycle.connect(lambda s: self.write_log(s))
        self.sync_worker.progress_update.connect(lambda pct, txt: (self.progress.setValue(pct), self.write_log(txt)))
        self.sync_worker.security_warning.connect(lambda m: QMessageBox.critical(self, "SECURITY", m))
        self.sync_worker.start()
        self.btn_sync.setText("STOP SYNC")
        self.write_log("Continuous sync started.")

    def burn_identity(self):
        """Remove saved onion private key; a new identity will be generated next server start."""
        if os.path.exists(KEY_FILE):
            try:
                shutil.copyfile(KEY_FILE, KEY_FILE_BAK)
            except: pass
            try:
                os.remove(KEY_FILE)
            except: pass
        QMessageBox.information(self, "Identity removed", "Saved identity removed. Start the server to create a new one.")
        self.write_log("User removed identity")

    # -------------------------
    # Ephemeral token UI actions
    # -------------------------
    def generate_one_time_token(self):
        """
        Generate a one-time token for manual sharing.
        Token can be bound to the current ephemeral snapshot (safer).
        """
        try:
            ttl_min = max(1, int(self.input_token_ttl.text().strip()))
        except Exception:
            ttl_min = ONE_TIME_TOKEN_TTL_DEFAULT // 60
        note = self.input_token_note.text().strip() or "shared_manually"
        expires = time.time() + ttl_min * 60
        token = secrets.token_urlsafe(28)

        if SWARM_FOLDER and os.path.exists(SWARM_FOLDER):
            dlp_manager.load_rules()
            virtual_map = {}
            files_data = []
            for root, dirs, files in os.walk(SWARM_FOLDER):
                for file in files:
                    full_path = os.path.join(root, file)
                    if not is_within_directory(SWARM_FOLDER, full_path):
                        continue
                    rel_path = os.path.relpath(full_path, SWARM_FOLDER).replace("\\", "/")
                    fake = dlp_manager.make_fake_name(rel_path, ADMIN_KEY_BYTES)
                    try:
                        stat = os.stat(full_path)
                        age_hours = int((time.time() - stat.st_mtime)//3600)
                        size = stat.st_size
                    except Exception:
                        age_hours = -1; size = -1
                    files_data.append({"path": fake, "size": size, "age_hours": age_hours})
                    virtual_map[fake] = full_path
            map_json = json.dumps(files_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            sig = hmac.new(ADMIN_KEY_BYTES, map_json, hashlib.sha256).hexdigest()
            map_id = secrets.token_hex(8)
            map_token = secrets.token_urlsafe(24)
            _EPHEMERAL_MAPS[map_id] = {"map": virtual_map, "sig": sig, "token": map_token, "ts": time.time()}
            bound_map_id = map_id
        else:
            bound_map_id = None

        _ONE_TIME_TOKENS[token] = {"type": "oneoff", "map_id": bound_map_id, "expires": expires, "note": note}
        self.input_generated_token.setText(token)
        self.write_log(f"Generated one-time token (ttl {ttl_min}min) bound_map={bound_map_id} note={note}")
        try:
            tlog = os.path.join(CONFIG_DIR, "one_time_token_log.jsonl")
            with open(tlog, "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": int(time.time()), "token_hash": hashlib.sha256(token.encode()).hexdigest(), "expires": int(expires), "note": note, "bound_map": bound_map_id}) + "\n")
        except Exception:
            pass

    def copy_generated_token(self):
        token = self.input_generated_token.text().strip()
        if not token:
            QMessageBox.information(self, "Token", "No token generated")
            return
        cb = QApplication.clipboard()
        cb.setText(token)
        QMessageBox.information(self, "Copied", "Token copied to clipboard")

# -------------------------
# Entrypoint
# -------------------------
def main():
    app_qt = QApplication(sys.argv)
    win = MainAppWindow()
    win.show()
    ensure_global_upload_bucket()
    sys.exit(app_qt.exec())

if __name__ == "__main__":
    main()
