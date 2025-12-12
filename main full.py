#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nishizumi Share - Secure Anonymous File Sharing
================================================

A privacy-focused file synchronization system using Tor hidden services for
secure team collaboration. Enables peer-to-peer file sharing without exposing
IP addresses or requiring central servers.

Features:
    - Complete anonymity via .onion addresses
    - Optional antivirus scanning (disabled by default)
    - Data leak protection with filename sanitization
    - Rate-limited uploads/downloads
    - Ephemeral access tokens
    - Cross-platform support (Windows, Linux, macOS)

Version: 2.2.1
License: MIT
Author: nishizumi-maho
Repository: https://github.com/nishizumi-maho/nishizumi-share

Copyright (c) 2025 nishizumi-maho

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

# Standard library imports
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
import re
from pathlib import Path
from functools import wraps
from typing import Dict, Optional, Tuple, List
from urllib.parse import quote

# Third-party imports - Web server
from flask import Flask, request, jsonify, Response

try:
    from waitress import serve
except ImportError:
    serve = None  # Fallback to Flask dev server if waitress unavailable

# Third-party imports - GUI
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QMessageBox, QTextEdit, QPlainTextEdit, QHBoxLayout,
    QProgressBar, QCheckBox, QTabWidget, QGroupBox, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import pyqtSignal, QThread, QObject, Qt

# Note: requests is imported inside worker threads to avoid import-time failures

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

# Application metadata
APP_NAME = "NishizumiShare"
APP_VERSION = "2.2.1"

# Platform-specific configuration directory
if sys.platform == "win32":
    CONFIG_DIR = os.path.join(
        os.environ.get("APPDATA", os.path.expanduser("~")), 
        APP_NAME
    )
else:
    CONFIG_DIR = os.path.join(os.path.expanduser("~"), f".{APP_NAME}")

os.makedirs(CONFIG_DIR, exist_ok=True)

# Persistent storage files
KEY_FILE = os.path.join(CONFIG_DIR, "onion_private_key")
KEY_FILE_BAK = os.path.join(CONFIG_DIR, "onion_private_key.bak")
PEERS_FILE = os.path.join(CONFIG_DIR, "team_peers.txt")
RULES_FILE = os.path.join(CONFIG_DIR, "security_rules.txt")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
TOR_DATA_DIR = os.path.join(CONFIG_DIR, "tor_data")
SCAN_CACHE_FILE = os.path.join(CONFIG_DIR, "scan_cache.json")
ADMIN_KEY_FILE = os.path.join(CONFIG_DIR, "admin_key")

os.makedirs(TOR_DATA_DIR, exist_ok=True)

# Network configuration
FLASK_PORT = 5000          # Local Flask server port
SOCKS_PORT = 9050          # Tor SOCKS proxy port
CTRL_PORT = 9051           # Tor control port
CTRL_HOST = "127.0.0.1"    # Localhost only

# Security & performance defaults
DEFAULT_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MB per file
DEFAULT_DOWNLOAD_LIMIT_BPS = 2 * 1024 * 1024    # 2 MB/s download
DEFAULT_UPLOAD_LIMIT_BPS = 2 * 1024 * 1024      # 2 MB/s upload
RATE_LIMIT_WINDOW = 60                           # Seconds
RATE_LIMIT_REQUESTS = 60                         # Max requests per window
EPHEMERAL_TTL = 600                              # Ephemeral map lifetime (10 min)
ONE_TIME_TOKEN_TTL_DEFAULT = 3600                # One-time token default TTL (1 hour)

# Antivirus configuration
DEFENDER_PATH = os.path.expandvars(
    r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"
)
FORCE_AV_SCAN_DEFAULT = False  # Default: AV scanning disabled
AV_DISABLE_GLOBAL = True       # Global override: forces AV off

# ==============================================================================
# LOGGING SETUP
# ==============================================================================

logger = logging.getLogger("nishizumi_secure")
logger.setLevel(logging.INFO)

# Console handler with formatted output
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.addHandler(console_handler)

# ==============================================================================
# FLASK APPLICATION
# ==============================================================================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = DEFAULT_MAX_DOWNLOAD_BYTES

# ==============================================================================
# GLOBAL STATE
# ==============================================================================

SWARM_FOLDER: str = ""            # Engineer's shared folder path
SECURITY_ALERT_MODE: bool = False # Global security alert flag
FILES_SERVED_COUNT: int = 0       # Total files served counter

# ==============================================================================
# SETTINGS MANAGEMENT
# ==============================================================================

DEFAULT_SETTINGS = {
    "tor_path": "",
    "use_embedded_tor": True,
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

# Load existing settings or use defaults
if os.path.exists(SETTINGS_FILE):
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            SETTINGS = json.load(f)
        # Ensure all default keys exist
        for key, value in DEFAULT_SETTINGS.items():
            if key not in SETTINGS:
                SETTINGS[key] = value
    except Exception:
        logger.warning("Failed to load settings, using defaults")
        SETTINGS = DEFAULT_SETTINGS.copy()
else:
    SETTINGS = DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f, indent=2)
    except Exception:
        logger.error("Failed to create initial settings file")


def save_settings() -> None:
    """
    Persist current SETTINGS to disk with secure permissions.
    
    Creates a JSON file with mode 0o600 (owner read/write only) to protect
    sensitive configuration data.
    """
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f, indent=2)
        try:
            os.chmod(SETTINGS_FILE, 0o600)
        except Exception:
            pass  # Permissions may not be supported on all platforms
    except Exception:
        logger.exception("Failed to save settings")


# ==============================================================================
# HMAC KEY MANAGEMENT
# ==============================================================================

def _load_or_create_admin_key() -> str:
    """
    Load existing ADMIN_KEY or create a new one.
    
    The admin key is used for deterministic HMAC-based filename obfuscation,
    ensuring consistent fake names across sessions.
    
    Returns:
        str: Base64-encoded admin key
    """
    if os.path.exists(ADMIN_KEY_FILE):
        try:
            with open(ADMIN_KEY_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            logger.warning("Failed to read admin key, generating new one")
    
    # Generate new key
    key = secrets.token_urlsafe(48)
    try:
        with open(ADMIN_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(key)
        os.chmod(ADMIN_KEY_FILE, 0o600)
    except Exception:
        logger.error("Failed to save admin key")
    
    return key


ADMIN_KEY = _load_or_create_admin_key()
ADMIN_KEY_BYTES = ADMIN_KEY.encode()

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def safe_write_file(path: str, data: str, make_backup: bool = True) -> bool:
    """
    Atomically write data to a file with optional backup.
    
    Args:
        path: Target file path
        data: String data to write
        make_backup: Create .bak file before overwriting
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if make_backup and os.path.exists(path):
            try:
                shutil.copyfile(path, f"{path}.bak")
            except Exception:
                pass
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        
        return True
    except Exception:
        logger.exception(f"safe_write_file failed for {path}")
        return False


def load_json(path: str) -> Optional[dict]:
    """Load JSON from file, return None on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_json(path: str, obj: dict) -> bool:
    """Save object as JSON with secure permissions."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        logger.exception(f"save_json failed for {path}")
        return False


def sha256_of_file(path: str) -> str:
    """
    Calculate SHA256 hash of a file in streaming mode.
    
    Args:
        path: Path to file
        
    Returns:
        str: Hexadecimal digest
    """
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def is_within_directory(base_dir: str, target_path: str) -> bool:
    """
    Verify target_path is within base_dir (directory traversal protection).
    
    Args:
        base_dir: Base directory path
        target_path: Path to validate
        
    Returns:
        bool: True if target is within base, False otherwise
    """
    try:
        base = Path(base_dir).resolve()
        target = Path(target_path).resolve()
        return base == target or base in target.parents
    except Exception:
        return False


def mask_name(name: str) -> str:
    """
    Partially mask a filename for logging (privacy protection).
    
    Example: "secretfile.txt" -> "sec...txt"
    
    Args:
        name: Filename to mask
        
    Returns:
        str: Masked filename
    """
    if len(name) <= 8:
        return "****" + name[-2:]
    return name[:3] + "..." + name[-3:]


# ==============================================================================
# DATA LEAK PROTECTION (DLP)
# ==============================================================================

class DataProtectionManager:
    """
    Manages filename sanitization and deterministic obfuscation.
    
    Applies user-defined rules to replace sensitive terms in filenames,
    then generates deterministic fake names using HMAC to prevent leaking
    internal file structure.
    """
    
    def __init__(self):
        """Initialize with empty rules, load from disk if available."""
        self.rules: Dict[str, str] = {}
        self.virtual_map: Dict[str, str] = {}
        self.load_rules()
    
    def load_rules(self) -> None:
        """
        Load DLP rules from RULES_FILE.
        
        Format: private_term=PUBLIC_CODE (one per line)
        Example: internal=PUBLIC, CompanyName=TEAM
        """
        self.rules = {}
        if not os.path.exists(RULES_FILE):
            return
        
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        self.rules[key.lower()] = value
        except Exception:
            logger.exception("Failed to load DLP rules")
    
    def sanitize_component(self, component: str) -> str:
        """
        Sanitize a single path component.
        
        - Normalizes Unicode
        - Removes control characters
        - Replaces dangerous characters (path separators, etc.)
        - Applies DLP replacement rules
        - Truncates to 200 chars
        
        Args:
            component: Path component to sanitize
            
        Returns:
            str: Sanitized component
        """
        import unicodedata
        
        # Normalize Unicode
        sanitized = unicodedata.normalize("NFKC", component)
        
        # Remove/replace dangerous characters
        sanitized = re.sub(r'[\x00-\x1f<>:"|?*\']', "_", sanitized)
        sanitized = sanitized.replace("..", "_")
        
        # Apply DLP rules (case-insensitive)
        lower = sanitized.lower()
        for private_term, public_code in self.rules.items():
            if private_term in lower:
                idx = lower.find(private_term)
                sanitized = (
                    sanitized[:idx] + 
                    public_code + 
                    sanitized[idx + len(private_term):]
                )
                lower = sanitized.lower()
        
        return sanitized[:200]
    
    def make_fake_name(self, rel_path: str, key: bytes) -> str:
        """
        Create deterministic fake name for a relative path.
        
        Combines sanitized path with HMAC suffix for lookup while protecting
        sensitive information.
        
        Format: sanitized/path/to/file__<16-char-hmac>
        
        Args:
            rel_path: Original relative path
            key: HMAC key bytes
            
        Returns:
            str: Fake path with HMAC suffix
        """
        parts = rel_path.replace("\\", "/").split("/")
        sanitized_parts = [self.sanitize_component(p) for p in parts]
        sanitized_path = "/".join(sanitized_parts)
        
        # Generate deterministic HMAC suffix (16 hex chars)
        hmac_digest = hmac.new(key, rel_path.encode("utf-8"), hashlib.sha256)
        hmac_suffix = hmac_digest.hexdigest()[:16]
        
        return f"{sanitized_path}__{hmac_suffix}"


# Global DLP manager instance
dlp_manager = DataProtectionManager()

# ==============================================================================
# ANTIVIRUS SCANNING
# ==============================================================================

def load_scan_cache() -> dict:
    """Load AV scan cache from disk."""
    if os.path.exists(SCAN_CACHE_FILE):
        try:
            with open(SCAN_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


_scan_cache = load_scan_cache()


def save_scan_cache(cache: dict) -> None:
    """Persist AV scan cache to disk."""
    try:
        with open(SCAN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        try:
            os.chmod(SCAN_CACHE_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        logger.exception("Failed to save scan cache")


def scan_with_windows_defender(path: str, timeout: int = 60) -> Tuple[bool, str]:
    """
    Scan file with Microsoft Defender (Windows only).
    
    Args:
        path: File path to scan
        timeout: Scan timeout in seconds
        
    Returns:
        tuple: (is_clean, reason_string)
    """
    if not os.path.exists(DEFENDER_PATH):
        return False, "defender_not_found"
    
    cmd = [DEFENDER_PATH, "-Scan", "-ScanType", "3", "-File", path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        
        if result.returncode == 0:
            return True, "clean"
        else:
            # Capture error output (truncated)
            output = (
                result.stdout.decode(errors="ignore") + 
                result.stderr.decode(errors="ignore")
            )[:400]
            return False, f"defender_nonzero:{result.returncode}:{output}"
    
    except subprocess.TimeoutExpired:
        return False, "defender_timeout"
    except Exception as e:
        return False, f"defender_exception:{str(e)[:200]}"


def scan_with_clamav(path: str, timeout: int = 120) -> Tuple[bool, str]:
    """
    Scan file with ClamAV (Linux/macOS).
    
    Tries clamdscan (daemon) first, falls back to clamscan.
    
    Args:
        path: File path to scan
        timeout: Scan timeout in seconds
        
    Returns:
        tuple: (is_clean, reason_string)
    """
    for exe in ("clamdscan", "clamscan"):
        if not shutil.which(exe):
            continue
        
        cmd = [exe, "--no-summary", path]
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
            output = (
                result.stdout.decode(errors="ignore") + 
                result.stderr.decode(errors="ignore")
            )[:400]
            
            if result.returncode == 0:
                return True, "clean"
            elif result.returncode == 1:
                return False, f"clam_infected:{output}"
            else:
                return False, f"clam_error:{result.returncode}:{output}"
        
        except subprocess.TimeoutExpired:
            return False, "clam_timeout"
        except Exception as e:
            return False, f"clam_exception:{str(e)[:200]}"
    
    return False, "clam_not_found"


def av_scan_file(path: str, force_scan: bool = False) -> Tuple[bool, str]:
    """
    High-level AV scanning wrapper with caching.
    
    Behavior:
        1. If AV_DISABLE_GLOBAL is True, always returns (True, "disabled")
        2. Checks settings for force_av_scan preference
        3. Uses cached result if available (24h validity)
        4. Attempts platform-specific scanning (Defender/ClamAV)
        5. Caches result for future lookups
    
    Args:
        path: File path to scan
        force_scan: Override settings and force scan
        
    Returns:
        tuple: (is_clean, reason_string)
    """
    # Global override: AV disabled entirely
    if AV_DISABLE_GLOBAL:
        return True, "av_disabled_global"
    
    # Check user settings
    if not SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT) and not force_scan:
        return True, "av_disabled_by_settings"
    
    # Calculate file hash for cache lookup
    try:
        sha = sha256_of_file(path)
    except Exception as e:
        return False, f"hash_error:{str(e)[:200]}"
    
    # Check cache (24h validity)
    now = int(time.time())
    cached = _scan_cache.get(sha)
    if cached and (now - cached.get("ts", 0) < 24 * 3600):
        return cached.get("clean", False), cached.get("reason", "cached")
    
    # Perform actual scan
    if sys.platform == "win32":
        is_clean, reason = scan_with_windows_defender(path, timeout=60)
    else:
        is_clean, reason = scan_with_clamav(path, timeout=120)
    
    # Update cache
    _scan_cache[sha] = {"clean": is_clean, "reason": reason, "ts": now}
    save_scan_cache(_scan_cache)
    
    # If forcing scan and file is dirty, return failure
    if not is_clean and force_scan:
        return False, reason
    
    return is_clean, reason


# ==============================================================================
# EPHEMERAL TOKENS & MAPS
# ==============================================================================

# In-memory storage for ephemeral file maps and one-time access tokens
_EPHEMERAL_MAPS: Dict[str, Dict] = {}
_ONE_TIME_TOKENS: Dict[str, Dict] = {}


def cleanup_ephemeral_maps() -> None:
    """Remove expired ephemeral maps (TTL: 10 minutes)."""
    now = time.time()
    for map_id in list(_EPHEMERAL_MAPS.keys()):
        if now - _EPHEMERAL_MAPS[map_id].get("ts", 0) > EPHEMERAL_TTL:
            _EPHEMERAL_MAPS.pop(map_id, None)


def cleanup_one_time_tokens() -> None:
    """Remove expired one-time tokens."""
    now = time.time()
    for token in list(_ONE_TIME_TOKENS.keys()):
        if now > _ONE_TIME_TOKENS[token].get("expires", 0):
            _ONE_TIME_TOKENS.pop(token, None)


# ==============================================================================
# RATE LIMITING
# ==============================================================================

_rate_store: Dict[str, Dict] = {}


def rate_limited(f):
    """
    Flask route decorator for global rate limiting.
    
    In Tor hidden service context, all requests appear from localhost,
    so we implement global rate limiting instead of per-IP limiting.
    
    Limits: 600 requests per 60 seconds (10x RATE_LIMIT_REQUESTS)
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        global_bucket = _rate_store.setdefault("global", {"timestamps": []})
        now = time.time()
        
        # Remove timestamps outside the window
        global_bucket["timestamps"] = [
            ts for ts in global_bucket["timestamps"] 
            if now - ts < RATE_LIMIT_WINDOW
        ]
        
        # Check if limit exceeded
        if len(global_bucket["timestamps"]) >= (RATE_LIMIT_REQUESTS * 10):
            return jsonify({"error": "global_rate_limit_exceeded"}), 429
        
        global_bucket["timestamps"].append(now)
        return f(*args, **kwargs)
    
    return wrapped


def require_map_or_token(f):
    """
    Flask route decorator for token-based authentication.
    
    Accepts either:
        - Ephemeral map token (issued with /list response)
        - One-time UI token (manually generated)
    
    Authorization header format: Bearer <token>
    """
    @wraps(f)
    def wrapped(map_id, *args, **kwargs):
        cleanup_ephemeral_maps()
        cleanup_one_time_tokens()
        
        # Extract Bearer token from Authorization header
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        
        token = auth.split(" ", 1)[1]
        
        # Check ephemeral map token
        entry = _EPHEMERAL_MAPS.get(map_id)
        if entry and hmac.compare_digest(token, entry.get("token", "")):
            return f(map_id, *args, **kwargs)
        
        # Check one-time token
        ot = _ONE_TIME_TOKENS.get(token)
        if ot and time.time() < ot.get("expires", 0):
            bound_map = ot.get("map_id")
            if bound_map and bound_map != map_id:
                return jsonify({"error": "token_not_for_map"}), 403
            return f(map_id, *args, **kwargs)
        
        return jsonify({"error": "invalid_or_expired_token"}), 401
    
    return wrapped


# ==============================================================================
# TOKEN BUCKET (RATE THROTTLING)
# ==============================================================================

class TokenBucket:
    """
    Token bucket algorithm for smooth bandwidth throttling.
    
    Allows burst traffic up to capacity, then refills at a steady rate.
    Used for both upload and download rate limiting.
    """
    
    def __init__(self, capacity_bytes: int, fill_rate_bps: float):
        """
        Initialize token bucket.
        
        Args:
            capacity_bytes: Maximum burst size (bucket capacity)
            fill_rate_bps: Steady-state rate (bytes per second)
        """
        self.capacity = float(capacity_bytes)
        self.tokens = float(capacity_bytes)  # Start full
        self.fill_rate = float(fill_rate_bps)
        self.timestamp = time.monotonic()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.timestamp
        
        if elapsed <= 0:
            return
        
        # Add tokens based on fill rate
        added = elapsed * self.fill_rate
        self.tokens = min(self.capacity, self.tokens + added)
        self.timestamp = now
    
    def consume(self, num_bytes: int) -> None:
        """
        Consume tokens, blocking if insufficient.
        
        Args:
            num_bytes: Number of bytes to consume
        """
        if self.fill_rate <= 0:
            return  # Unlimited
        
        needed = float(num_bytes)
        
        while True:
            self._refill()
            
            if self.tokens >= needed:
                self.tokens -= needed
                return
            
            # Calculate sleep time for shortage
            shortage = needed - self.tokens
            wait_time = max(0.001, min(0.5, shortage / max(1.0, self.fill_rate)))
            time.sleep(wait_time)


# Global upload throttle bucket
GLOBAL_UPLOAD_BUCKET: Optional[TokenBucket] = None


def ensure_global_upload_bucket() -> None:
    """Initialize or update the global upload rate limiter."""
    global GLOBAL_UPLOAD_BUCKET
    
    upload_limit = SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT_BPS)
    upload_limit = upload_limit or DEFAULT_UPLOAD_LIMIT_BPS
    
    # Allow 2-second burst capacity
    capacity = int(upload_limit * 2)
    GLOBAL_UPLOAD_BUCKET = TokenBucket(capacity, float(upload_limit))


# ==============================================================================
# HMAC SUFFIX STRIPPING
# ==============================================================================

HMAC_SUFFIX_RE = re.compile(r'__(?P<h>[0-9a-fA-F]{16})$')


def strip_hmac_from_fake(fake_path: str) -> str:
    """
    Remove HMAC suffix from fake filename.
    
    The server appends __<16hexchars> to obfuscated filenames. Clients
    strip this suffix when saving locally to restore readable names.
    
    Example: "car/setup__1234567890abcdef" -> "car/setup"
    
    Args:
        fake_path: Obfuscated path with HMAC suffix
        
    Returns:
        str: Path with suffix removed
    """
    try:
        parts = fake_path.replace("\\", "/").split("/")
        if not parts:
            return fake_path
        
        last = parts[-1]
        match = HMAC_SUFFIX_RE.search(last)
        
        if match:
            last = last[:match.start()]
            parts[-1] = last
            return "/".join(parts)
        
        return fake_path
    except Exception:
        return fake_path


# ==============================================================================
# FLASK ROUTES
# ==============================================================================

@app.route("/list", methods=["GET"])
@rate_limited
def list_files():
    """
    List available files with ephemeral access token.
    
    Returns JSON containing:
        - files: Array of {path, size, age_hours}
        - map_id: Ephemeral map identifier
        - map_token: Bearer token for downloads
        - map_sig: HMAC signature of file list
        - security_alert: Boolean flag
    
    Paths are obfuscated using DLP rules + HMAC suffixes.
    Map expires after EPHEMERAL_TTL (10 minutes).
    """
    cleanup_ephemeral_maps()
    
    global SWARM_FOLDER
    if not SWARM_FOLDER or not os.path.exists(SWARM_FOLDER):
        return jsonify({"error": "node_not_ready"}), 404
    
    # Reload DLP rules before building map
    dlp_manager.load_rules()
    
    files_data = []
    virtual_map = {}
    
    try:
        # Walk shared directory
        for root, dirs, files in os.walk(SWARM_FOLDER):
            for filename in files:
                full_path = os.path.join(root, filename)
                
                # Security check: prevent directory traversal
                if not is_within_directory(SWARM_FOLDER, full_path):
                    logger.warning(
                        f"Skipping file outside swarm folder: {mask_name(filename)}"
                    )
                    continue
                
                # Calculate relative path
                rel_path = os.path.relpath(full_path, SWARM_FOLDER)
                rel_path = rel_path.replace("\\", "/")
                
                # Generate fake name with HMAC
                fake_name = dlp_manager.make_fake_name(rel_path, ADMIN_KEY_BYTES)
                
                # Gather file metadata
                try:
                    stat = os.stat(full_path)
                    age_hours = int((time.time() - stat.st_mtime) // 3600)
                    size = stat.st_size
                except Exception:
                    age_hours = -1
                    size = -1
                
                files_data.append({
                    "path": fake_name,
                    "size": size,
                    "age_hours": age_hours
                })
                virtual_map[fake_name] = full_path
        
        # Create HMAC signature of file list
        map_json = json.dumps(
            files_data, 
            separators=(",", ":"), 
            ensure_ascii=False
        ).encode("utf-8")
        
        signature = hmac.new(
            ADMIN_KEY_BYTES, 
            map_json, 
            hashlib.sha256
        ).hexdigest()
        
        # Generate ephemeral credentials
        map_id = secrets.token_hex(8)
        map_token = secrets.token_urlsafe(24)
        
        # Store ephemeral map
        _EPHEMERAL_MAPS[map_id] = {
            "map": virtual_map,
            "sig": signature,
            "token": map_token,
            "ts": time.time()
        }
        
        return jsonify({
            "root": "Repository",
            "files": files_data,
            "map_id": map_id,
            "map_sig": signature,
            "map_token": map_token,
            "security_alert": bool(SECURITY_ALERT_MODE)
        })
    
    except Exception:
        logger.exception("Failed to generate file list")
        return jsonify({"error": "internal_error"}), 500


def stream_file_with_bucket(
    path: str, 
    upload_bucket: Optional[TokenBucket], 
    chunk_size: int = 64 * 1024
):
    """
    Generator that streams file chunks with rate limiting.
    
    Args:
        path: File path to stream
        upload_bucket: Token bucket for throttling (or None for unlimited)
        chunk_size: Bytes per chunk
        
    Yields:
        bytes: File chunks
    """
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            
            # Apply rate limiting
            if upload_bucket:
                upload_bucket.consume(len(data))
            
            yield data


@app.route("/download/<map_id>/<path:fake_name>", methods=["GET"])
@rate_limited
@require_map_or_token
def download_file(map_id: str, fake_name: str):
    """
    Serve file from ephemeral map with authentication and AV scanning.
    
    Args:
        map_id: Ephemeral map identifier
        fake_name: Obfuscated filename (with HMAC suffix)
    
    Returns:
        Response: Streamed file with rate limiting, or error JSON
    
    Security:
        - Requires valid Bearer token
        - Validates map_id and fake_name
        - Prevents directory traversal
        - Optional AV scanning before serving
        - Rate-limited streaming via TokenBucket
    """
    # Retrieve ephemeral map
    entry = _EPHEMERAL_MAPS.get(map_id)
    if not entry:
        return jsonify({"error": "map_not_found"}), 404
    
    virtual_map = entry.get("map", {})
    
    # Resolve fake name to real path
    real_path = virtual_map.get(fake_name)
    if not real_path or not os.path.exists(real_path):
        return jsonify({"error": "file_not_found"}), 404
    
    # Security: prevent directory traversal
    if not is_within_directory(SWARM_FOLDER, real_path):
        logger.warning(f"Directory traversal attempt: {mask_name(fake_name)}")
        return jsonify({"error": "forbidden"}), 403
    
    # Optional AV scan
    force_scan = SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT)
    is_clean, reason = av_scan_file(real_path, force_scan=force_scan)
    
    if not is_clean:
        logger.warning(
            f"Blocked file by AV: {mask_name(os.path.basename(real_path))} "
            f"reason={reason}"
        )
        return jsonify({"error": "file_blocked_by_av", "reason": reason}), 403
    
    # Increment served counter
    global FILES_SERVED_COUNT
    FILES_SERVED_COUNT += 1
    
    # Ensure upload throttle is initialized
    ensure_global_upload_bucket()
    
    # Stream file with rate limiting
    response = Response(
        stream_file_with_bucket(real_path, GLOBAL_UPLOAD_BUCKET),
        mimetype="application/octet-stream"
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{os.path.basename(real_path)}"'
    )
    
    return response


# ==============================================================================
# TOR CONTROL PORT HELPERS
# ==============================================================================

def _send_cmd(sock: socket.socket, cmd: str) -> List[str]:
    """
    Send command to Tor control port and collect response.
    
    Args:
        sock: Connected socket to Tor control port
        cmd: Command string (will be terminated with \\r\\n)
        
    Returns:
        list: Response lines from Tor
    """
    if not cmd.endswith("\r\n"):
        cmd = cmd + "\r\n"
    
    try:
        sock.sendall(cmd.encode("utf-8"))
    except Exception:
        logger.exception("Failed to send command to Tor control port")
        return []
    
    sock.settimeout(5.0)
    data = b""
    lines = []
    
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            
            data += chunk
            
            if b"\r\n" in data:
                parts = data.split(b"\r\n")
                
                for part in parts[:-1]:
                    if part:
                        try:
                            lines.append(part.decode("utf-8", errors="ignore"))
                        except Exception:
                            lines.append(str(part))
                
                # Check for completion codes
                if lines and (lines[-1].startswith("250 ") or 
                             lines[-1].startswith("550 ")):
                    return lines
    except Exception:
        pass
    
    return lines


def _try_auth_cookie(sock: socket.socket, tor_data_dir: str) -> bool:
    """
    Attempt cookie-based authentication with Tor.
    
    Args:
        sock: Connected socket to Tor control port
        tor_data_dir: Directory containing control_auth_cookie
        
    Returns:
        bool: True if authentication succeeded
    """
    try:
        cookie_path = os.path.join(tor_data_dir, "control_auth_cookie")
        
        if os.path.exists(cookie_path):
            with open(cookie_path, "rb") as f:
                cookie_hex = f.read().hex()
            
            lines = _send_cmd(sock, f"AUTHENTICATE {cookie_hex}")
            if any(line.startswith("250") for line in lines):
                return True
    except Exception:
        logger.exception("Cookie authentication failed")
    
    # Fallback: try null authentication
    try:
        lines = _send_cmd(sock, 'AUTHENTICATE ""')
        if any(line.startswith("250") for line in lines):
            return True
    except Exception:
        pass
    
    return False


def _try_auth_password(sock: socket.socket, password: str) -> bool:
    """
    Attempt password authentication with Tor.
    
    Args:
        sock: Connected socket to Tor control port
        password: Control password
        
    Returns:
        bool: True if authentication succeeded
    """
    try:
        # Escape quotes in password
        escaped = password.replace('"', '\\"')
        cmd = f'AUTHENTICATE "{escaped}"'
        
        lines = _send_cmd(sock, cmd)
        if any(line.startswith("250") for line in lines):
            return True
    except Exception:
        logger.exception("Password authentication failed")
    
    return False


# ==============================================================================
# TOR MANAGER WORKER THREAD
# ==============================================================================

class TorManagerWorker(QThread):
    """
    Background thread that manages Tor process and Flask server.
    
    Responsibilities:
        1. Start Tor with generated control password
        2. Authenticate to control port
        3. Create/restore onion hidden service
        4. Run Flask application under Waitress WSGI server
    
    Signals:
        status_update(str): Progress messages for UI
        onion_ready(str): Emitted with .onion URL when service is ready
        identity_reset(): Emitted when identity is regenerated
    """
    
    status_update = pyqtSignal(str)
    onion_ready = pyqtSignal(str)
    identity_reset = pyqtSignal()
    
    def __init__(self, tor_exe_path: str):
        """
        Initialize Tor manager.
        
        Args:
            tor_exe_path: Path to tor executable
        """
        super().__init__()
        self.tor_exe_path = tor_exe_path
        self.control_password: Optional[str] = None
        self.hashed_password: Optional[str] = None
        self.tor_proc: Optional[subprocess.Popen] = None
        self._stop_requested = False
    
    def terminate_tor(self) -> None:
        """
        Forcefully terminate Tor process.
        
        Attempts graceful SIGTERM first, then SIGKILL if needed.
        """
        try:
            self._stop_requested = True
            
            if not self.tor_proc:
                return
            
            try:
                # Graceful termination
                self.tor_proc.terminate()
                
                try:
                    self.tor_proc.wait(timeout=3)
                    self.tor_proc = None
                    return
                except subprocess.TimeoutExpired:
                    pass
                
                # Forceful kill
                self.tor_proc.kill()
            except Exception:
                pass
            
            try:
                self.tor_proc.wait(timeout=2)
            except Exception:
                pass
            
            self.tor_proc = None
        
        except Exception:
            logger.exception("Failed to terminate Tor")
    
    def run(self) -> None:
        """Main thread execution: start Tor and Flask server."""
        
        # Validate Tor executable
        if not self.tor_exe_path or not os.path.exists(self.tor_exe_path):
            self.status_update.emit("Tor path missing or invalid")
            return
        
        tor_data_dir = TOR_DATA_DIR
        os.makedirs(tor_data_dir, exist_ok=True)
        
        self.status_update.emit("Generating Tor control password...")
        
        # Generate hashed control password
        password = secrets.token_urlsafe(20)
        hashed = None
        
        try:
            result = subprocess.run(
                [self.tor_exe_path, "--hash-password", password],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = (result.stdout or "") + (result.stderr or "")
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            
            if lines:
                candidate = lines[-1]
                if len(candidate) > 8:
                    hashed = candidate
        except Exception:
            hashed = None
        
        # Build Tor command line
        args = [
            self.tor_exe_path,
            "--SocksPort", str(SOCKS_PORT),
            "--ControlPort", str(CTRL_PORT),
            "--DataDirectory", tor_data_dir
        ]
        
        if hashed:
            args += ["--HashedControlPassword", hashed]
            self.control_password = password
            self.hashed_password = hashed
            self.status_update.emit("Starting Tor with hashed control password...")
        else:
            self.status_update.emit("Starting Tor with cookie authentication...")
        
        # Start Tor process
        try:
            creationflags = 0
            if sys.platform == 'win32':
                creationflags = 0x08000000  # CREATE_NO_WINDOW
            
            self.tor_proc = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags
            )
        except Exception as e:
            self.status_update.emit(f"Failed to start Tor: {e}")
            return
        
        # Wait for control port to become available
        sock = None
        for _ in range(30):
            if self._stop_requested:
                break
            
            try:
                sock = socket.create_connection((CTRL_HOST, CTRL_PORT), timeout=5)
                break
            except Exception:
                time.sleep(1)
        
        if not sock:
            self.status_update.emit("Control port not reachable")
            try:
                if self.tor_proc:
                    self.tor_proc.kill()
            except Exception:
                pass
            self.tor_proc = None
            return
        
        # Authenticate to control port
        authenticated = False
        
        if self.control_password:
            if _try_auth_password(sock, self.control_password):
                authenticated = True
            else:
                self.status_update.emit("Password auth failed, trying cookie...")
        
        if not authenticated:
            if _try_auth_cookie(sock, tor_data_dir):
                authenticated = True
        
        if not authenticated:
            self.status_update.emit("Could not authenticate to Tor control port")
            try:
                if self.tor_proc:
                    self.tor_proc.kill()
            except Exception:
                pass
            self.tor_proc = None
            return
        
        # Create or restore onion hidden service
        service_id = None
        private_key = None
        
        try:
            # Try to restore existing key
            if os.path.exists(KEY_FILE):
                try:
                    with open(KEY_FILE, "r", encoding="utf-8") as f:
                        key_data = f.read().strip()
                    
                    if ":" in key_data:
                        key_type, key_blob = key_data.split(":", 1)
                    else:
                        key_type, key_blob = "ED25519-V3", key_data
                    
                    response = _send_cmd(
                        sock, 
                        f"ADD_ONION {key_type}:{key_blob} Port=80,{FLASK_PORT}"
                    )
                    
                    for line in response:
                        if "ServiceID=" in line:
                            service_id = line.split("ServiceID=", 1)[1].strip()
                        if "PrivateKey=" in line:
                            private_key = line.split("PrivateKey=", 1)[1].strip()
                
                except Exception:
                    logger.exception("Failed to restore existing key")
            
            # Create new service if restore failed
            if not service_id:
                response = _send_cmd(
                    sock, 
                    f"ADD_ONION NEW:ED25519-V3 Port=80,{FLASK_PORT}"
                )
                
                for line in response:
                    if "ServiceID=" in line:
                        service_id = line.split("ServiceID=", 1)[1].strip()
                    if "PrivateKey=" in line:
                        private_key = line.split("PrivateKey=", 1)[1].strip()
                
                # Save new key
                if private_key:
                    safe_write_file(KEY_FILE, private_key, make_backup=False)
                    try:
                        os.chmod(KEY_FILE, 0o600)
                    except Exception:
                        pass
        
        except Exception:
            logger.exception("Failed to create onion service")
        
        # Emit onion URL
        onion_url = f"http://{service_id}.onion" if service_id else "unknown"
        self.onion_ready.emit(onion_url)
        self.status_update.emit(f"Service ready: {onion_url}")
        
        # Run Flask application (blocking)
        try:
            if serve is None:
                self.status_update.emit(
                    "Waitress not available, using Flask dev server"
                )
                app.run(port=FLASK_PORT, use_reloader=False, threaded=True)
            else:
                # Production WSGI server
                serve(app, host="127.0.0.1", port=FLASK_PORT, threads=4)
        except Exception:
            logger.exception("Flask/Waitress server failed")


# ==============================================================================
# CLIENT SYNC WORKER THREAD
# ==============================================================================

class SwarmSyncWorker(QThread):
    """
    Background thread that continuously syncs files from peers.
    
    Poll cycle:
        1. Contact each peer's /list endpoint
        2. Download new/changed files to quarantine
        3. Optional AV scan
        4. Atomic move to final destination
        5. Wait 30 seconds, repeat
    
    Signals:
        log(str): Log message for UI
        finished_cycle(str): Summary after each sync cycle
        security_warning(str): Security alert from peer
        progress_update(int, str): Download progress (percent, filename)
    """
    
    log = pyqtSignal(str)
    finished_cycle = pyqtSignal(str)
    security_warning = pyqtSignal(str)
    progress_update = pyqtSignal(int, str)
    
    def __init__(
        self, 
        peers_list: List[str], 
        save_dir: str, 
        team_name: str,
        sync_mode: int,
        only_sto: bool,
        scan_virus: bool
    ):
        """
        Initialize sync worker.
        
        Args:
            peers_list: List of peer .onion URLs
            save_dir: Local destination directory
            team_name: Team subfolder name
            sync_mode: 2=Simple Mirror, 3=Smart Mode (per-car folders)
            only_sto: Only download .sto files
            scan_virus: Enable AV scanning (overrides settings)
        """
        super().__init__()
        self.peers = [p.strip() for p in peers_list if p.strip()]
        self.save_dir = save_dir
        self.team_name = team_name
        self.sync_mode = sync_mode
        self.only_sto = only_sto
        self.scan_virus = scan_virus
        self.running = True
    
    def stop(self) -> None:
        """Signal worker to stop gracefully."""
        self.running = False
    
    def is_safe_path(self, base: str, path: str) -> bool:
        """Verify path is within base directory (traversal protection)."""
        try:
            base_abs = os.path.abspath(base)
            path_abs = os.path.abspath(path)
            return os.path.commonpath([base_abs, path_abs]) == base_abs
        except Exception:
            return False
    
    def write_log(self, msg: str) -> None:
        """Emit log message to UI."""
        self.log.emit(msg)
    
    def run(self) -> None:
        """Main sync loop: poll peers, download files, repeat."""
        import requests
        
        # Initialize download throttle
        download_limit = SETTINGS.get("download_limit_bps", DEFAULT_DOWNLOAD_LIMIT_BPS)
        download_limit = download_limit or DEFAULT_DOWNLOAD_LIMIT_BPS
        dl_bucket = TokenBucket(int(download_limit * 2), float(download_limit))
        
        chunk_size = 64 * 1024
        
        # Configure SOCKS5h proxy (preserves .onion)
        proxies = {
            'http': f'socks5h://127.0.0.1:{SOCKS_PORT}',
            'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'
        }
        
        while self.running:
            self.write_log("=== Starting sync cycle ===")
            total_new = 0
            
            for peer in self.peers:
                if not self.running:
                    break
                
                if not peer.endswith(".onion"):
                    continue
                
                peer_url = peer if peer.startswith("http") else f"http://{peer}"
                
                try:
                    # Fetch file list
                    response = requests.get(
                        f"{peer_url}/list",
                        proxies=proxies,
                        timeout=30
                    )
                    
                    if response.status_code != 200:
                        continue
                    
                    data = response.json()
                    
                    # Check security alert
                    if data.get("security_alert"):
                        self.security_warning.emit(
                            f"Peer {peer} reports security alert!"
                        )
                    
                    map_id = data.get("map_id")
                    map_token = data.get("map_token")
                    
                    if not map_id or not map_token:
                        continue
                    
                    remote_files = data.get("files", [])
                    
                    for file_desc in remote_files:
                        if not self.running:
                            break
                        
                        fake_path = file_desc.get("path")
                        
                        # Filter by extension if requested
                        if self.only_sto and ".sto" not in fake_path.lower():
                            continue
                        
                        # Strip HMAC suffix for local filename
                        clean_path = fake_path.replace("\\", "/")
                        clean_path = strip_hmac_from_fake(clean_path)
                        
                        # Map to local path based on sync mode
                        if self.sync_mode == 3:  # Smart Mode
                            parts = clean_path.split("/")
                            if len(parts) > 1:
                                car = parts[0]
                                rest = "/".join(parts[1:])
                                final_rel = os.path.join(car, self.team_name, rest)
                            else:
                                final_rel = os.path.join(
                                    "_General", 
                                    self.team_name, 
                                    parts[0]
                                )
                        elif self.sync_mode == 2:  # Simple Mirror
                            final_rel = os.path.join(self.team_name, clean_path)
                        else:
                            final_rel = clean_path
                        
                        local_path = os.path.join(self.save_dir, final_rel)
                        
                        # Check if download needed
                        should_download = False
                        if not os.path.exists(local_path):
                            should_download = True
                        else:
                            stat = os.stat(local_path)
                            remote_size = file_desc.get("size", -1)
                            if remote_size >= 0 and remote_size != stat.st_size:
                                should_download = True
                        
                        if not should_download:
                            continue
                        
                        # Security check
                        if not self.is_safe_path(self.save_dir, local_path):
                            continue
                        
                        filename = os.path.basename(local_path)
                        size = file_desc.get("size", 0)
                        
                        # Skip oversized files
                        max_size = SETTINGS.get("max_file_size", DEFAULT_MAX_DOWNLOAD_BYTES)
                        if size and size > max_size:
                            self.write_log(f"Skipping large file: {filename}")
                            continue
                        
                        # Download to quarantine
                        tmp_dir = os.path.join(self.save_dir, ".quarantine")
                        os.makedirs(tmp_dir, exist_ok=True)
                        
                        tmp_path = os.path.join(
                            tmp_dir, 
                            secrets.token_hex(8) + "_" + filename
                        )
                        
                        headers = {"Authorization": f"Bearer {map_token}"}
                        
                        try:
                            # Download file
                            with requests.get(
                                f"{peer_url}/download/{quote(map_id)}/"
                                f"{quote(fake_path, safe='')}",
                                proxies=proxies,
                                stream=True,
                                timeout=120,
                                headers=headers
                            ) as file_response:
                                
                                if file_response.status_code != 200:
                                    self.write_log(
                                        f"Failed: {filename} "
                                        f"(HTTP {file_response.status_code})"
                                    )
                                    continue
                                
                                total_length = file_response.headers.get("content-length")
                                downloaded = 0
                                
                                with open(tmp_path, "wb") as outfile:
                                    for chunk in file_response.iter_content(chunk_size):
                                        if not self.running:
                                            break
                                        if not chunk:
                                            continue
                                        
                                        # Apply rate limiting
                                        dl_bucket.consume(len(chunk))
                                        outfile.write(chunk)
                                        downloaded += len(chunk)
                                        
                                        # Update progress
                                        if total_length:
                                            percent = int(
                                                100 * downloaded / int(total_length)
                                            )
                                            self.progress_update.emit(
                                                percent, 
                                                f"Downloading {filename}"
                                            )
                            
                            try:
                                os.chmod(tmp_path, 0o600)
                            except Exception:
                                pass
                            
                            # AV scan
                            force_av = SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT)
                            is_clean, reason = av_scan_file(tmp_path, force_scan=force_av)
                            
                            if not is_clean:
                                try:
                                    os.remove(tmp_path)
                                except Exception:
                                    pass
                                self.write_log(f"AV blocked: {filename} ({reason})")
                                continue
                            
                            # Move to final location
                            os.makedirs(os.path.dirname(local_path), exist_ok=True)
                            
                            try:
                                os.replace(tmp_path, local_path)
                            except Exception:
                                # Fallback: copy + delete
                                try:
                                    shutil.copyfile(tmp_path, local_path)
                                    os.remove(tmp_path)
                                except Exception:
                                    self.write_log(
                                        f"Failed to move: {filename}"
                                    )
                                    continue
                            
                            # Set timestamp
                            os.utime(local_path, (time.time(), int(time.time())))
                            
                            total_new += 1
                            self.progress_update.emit(100, f"Saved {filename}")
                        
                        except Exception:
                            logger.exception("Download exception")
                            try:
                                if os.path.exists(tmp_path):
                                    os.remove(tmp_path)
                            except Exception:
                                pass
                
                except Exception:
                    logger.exception(f"Peer sync exception: {peer}")
            
            self.finished_cycle.emit(f"Cycle complete. New files: {total_new}")
            
            # Wait 30 seconds before next cycle
            for _ in range(30):
                if not self.running:
                    break
                time.sleep(1)


# ==============================================================================
# MAIN APPLICATION WINDOW
# ==============================================================================

class FlaskSignals(QObject):
    """Bridge for Flask callbacks to Qt signals."""
    file_served = pyqtSignal(str)


flask_bridge = FlaskSignals()


class MainAppWindow(QWidget):
    """
    Main application window with three tabs:
        - Client: Download from peers
        - Engineer: Share files, manage tokens
        - System: Tor configuration, logs
    """
    
    def __init__(self):
        """Initialize main window."""
        super().__init__()
        self.setWindowTitle(f"Nishizumi Share — v{APP_VERSION}")
        self.resize(960, 820)
        
        self.tor_worker: Optional[TorManagerWorker] = None
        self.sync_worker: Optional[SwarmSyncWorker] = None
        self.served_count = 0
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self) -> None:
        """Build user interface."""
        layout = QVBoxLayout(self)
        
        # Global status indicator
        self.lbl_global_status = QLabel("SERVER NOT RUNNING")
        self.lbl_global_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_global_status.setStyleSheet(
            "background:#555; color:#fff; padding:8px; "
            "font-weight:bold; border-radius:6px;"
        )
        layout.addWidget(self.lbl_global_status)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # === CLIENT TAB ===
        self._build_client_tab()
        
        # === ENGINEER TAB ===
        self._build_engineer_tab()
        
        # === SYSTEM TAB ===
        self._build_system_tab()
        
        layout.addWidget(self.tabs)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        
        # Connect Flask bridge
        flask_bridge.file_served.connect(self.on_file_served)
    
    def _build_client_tab(self) -> None:
        """Build the Client tab UI."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Destination folder
        layout.addWidget(QLabel(
            "<b>1) Destination folder (where setups will be saved)</b>"
        ))
        
        h1 = QHBoxLayout()
        self.btn_dest = QPushButton("📁 Select iRacing/setups folder")
        self.btn_dest.clicked.connect(self.choose_dest)
        self.lbl_dest = QLineEdit()
        self.lbl_dest.setReadOnly(True)
        h1.addWidget(self.btn_dest)
        h1.addWidget(self.lbl_dest)
        layout.addLayout(h1)
        
        # Peers
        layout.addWidget(QLabel("<b>2) Peers (one per line)</b>"))
        self.txt_peers = QPlainTextEdit()
        self.txt_peers.setPlaceholderText(
            "Paste team .onion links here (one per line)"
        )
        layout.addWidget(self.txt_peers)
        
        # Sync mode
        gb = QGroupBox("Sync configuration")
        gb_layout = QVBoxLayout()
        
        self.rb_smart = QRadioButton("Smart Mode (create per-car folder)")
        self.rb_smart.setChecked(True)
        self.rb_folder = QRadioButton("Simple Mirror (mirror as-is)")
        
        bg = QButtonGroup(self)
        bg.addButton(self.rb_smart, 3)
        bg.addButton(self.rb_folder, 2)
        
        gb_layout.addWidget(self.rb_smart)
        gb_layout.addWidget(self.rb_folder)
        
        team_row = QHBoxLayout()
        team_row.addWidget(QLabel("Team folder name:"))
        self.txt_team = QLineEdit("Team_Setups")
        team_row.addWidget(self.txt_team)
        gb_layout.addLayout(team_row)
        
        self.lbl_preview = QLabel(
            "Preview: iRacing/setups/[CAR]/Team_Setups/file.sto"
        )
        gb_layout.addWidget(self.lbl_preview)
        
        gb.setLayout(gb_layout)
        layout.addWidget(gb)
        
        # Explanation
        expl = QTextEdit()
        expl.setReadOnly(True)
        expl.setFixedHeight(110)
        expl.setHtml(
            "<b>Continuous synchronization</b><br>"
            "Polls peers every 30 seconds. For each new/changed file:<br>"
            "<ol>"
            "<li>Downloads to <code>.quarantine</code></li>"
            "<li>Optional AV scan (disabled by default)</li>"
            "<li>Moves to final destination</li>"
            "</ol>"
            "<i>Tip:</i> Adjust rate limits to avoid impacting gameplay."
        )
        layout.addWidget(expl)
        
        # Speed controls
        speed_row = QHBoxLayout()
        speed_row.addWidget(QLabel("Download limit (KB/s):"))
        self.input_dl = QLineEdit(str(
            int(SETTINGS.get("download_limit_bps", DEFAULT_DOWNLOAD_LIMIT_BPS) // 1024)
        ))
        speed_row.addWidget(self.input_dl)
        
        speed_row.addWidget(QLabel("Upload limit (KB/s):"))
        self.input_ul = QLineEdit(str(
            int(SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT_BPS) // 1024)
        ))
        speed_row.addWidget(self.input_ul)
        layout.addLayout(speed_row)
        
        # Sync button
        self.btn_sync = QPushButton("START SYNC")
        self.btn_sync.clicked.connect(self.toggle_sync)
        layout.addWidget(self.btn_sync)
        
        layout.addStretch(1)
        self.tabs.addTab(tab, "Client")
    
    def _build_engineer_tab(self) -> None:
        """Build the Engineer tab UI."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Share folder
        layout.addWidget(QLabel("<b>Share (outgoing folder)</b>"))
        h2 = QHBoxLayout()
        self.btn_orig = QPushButton("📁 Select outgoing folder")
        self.btn_orig.clicked.connect(self.choose_origin)
        self.lbl_orig = QLineEdit()
        self.lbl_orig.setReadOnly(True)
        h2.addWidget(self.btn_orig)
        h2.addWidget(self.lbl_orig)
        layout.addLayout(h2)
        
        # Onion link
        layout.addWidget(QLabel("<b>Your .onion link</b>"))
        self.txt_my_link = QLineEdit()
        self.txt_my_link.setReadOnly(True)
        layout.addWidget(self.txt_my_link)
        
        # DLP rules
        layout.addWidget(QLabel(
            "<b>DLP rules (example: internal=PUBLIC)</b>"
        ))
        self.txt_rules = QPlainTextEdit()
        layout.addWidget(self.txt_rules)
        
        btn_save_rules = QPushButton("Save rules")
        btn_save_rules.clicked.connect(self.save_rules)
        layout.addWidget(btn_save_rules)
        
        # Files served counter
        self.lbl_served = QLabel("Files served: 0")
        layout.addWidget(self.lbl_served)
        
        # Ephemeral token generator
        layout.addWidget(QLabel(
            "<b>Generate ephemeral token (one-time sharing)</b>"
        ))
        
        token_row = QHBoxLayout()
        self.input_token_ttl = QLineEdit(str(ONE_TIME_TOKEN_TTL_DEFAULT // 60))
        self.input_token_note = QLineEdit("One-off usage — send by DM")
        
        token_row.addWidget(QLabel("TTL (min):"))
        token_row.addWidget(self.input_token_ttl)
        token_row.addWidget(QLabel("Note:"))
        token_row.addWidget(self.input_token_note)
        layout.addLayout(token_row)
        
        gen_row = QHBoxLayout()
        self.btn_gen_token = QPushButton("Generate token")
        self.btn_gen_token.clicked.connect(self.generate_one_time_token)
        
        self.input_generated_token = QLineEdit()
        self.input_generated_token.setReadOnly(True)
        
        self.btn_copy_token = QPushButton("Copy token")
        self.btn_copy_token.clicked.connect(self.copy_generated_token)
        
        gen_row.addWidget(self.btn_gen_token)
        gen_row.addWidget(self.input_generated_token)
        gen_row.addWidget(self.btn_copy_token)
        layout.addLayout(gen_row)
        
        layout.addWidget(QLabel(
            "<i>Token is temporary — share only with intended recipient.</i>"
        ))
        
        self.tabs.addTab(tab, "Engineer")
    
    def _build_system_tab(self) -> None:
        """Build the System tab UI."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Tor configuration
        tor_row = QHBoxLayout()
        
        self.chk_embedded_tor = QCheckBox("Use embedded Tor (recommended)")
        self.chk_embedded_tor.setChecked(True)
        self.chk_embedded_tor.stateChanged.connect(self.on_tor_mode_changed)
        tor_row.addWidget(self.chk_embedded_tor)
        
        self.input_tor = QLineEdit()
        self.input_tor.setPlaceholderText(
            "Path to tor.exe (only if external is selected)"
        )
        
        self.btn_locate_tor = QPushButton("Locate Tor")
        self.btn_locate_tor.clicked.connect(self.locate_tor)
        
        self.btn_start_server = QPushButton("START SERVER")
        self.btn_start_server.clicked.connect(self.toggle_server)
        
        tor_row.addWidget(self.input_tor)
        tor_row.addWidget(self.btn_locate_tor)
        tor_row.addWidget(self.btn_start_server)
        layout.addLayout(tor_row)
        
        # AV and identity controls
        av_row = QHBoxLayout()
        
        self.chk_force_av = QCheckBox(
            "Force AV scan (block transfers if no scanner)"
        )
        self.chk_force_av.setChecked(
            SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT)
        )
        av_row.addWidget(self.chk_force_av)
        
        self.btn_regen = QPushButton("REGENERATE IDENTITY")
        self.btn_regen.clicked.connect(self.burn_identity)
        av_row.addWidget(self.btn_regen)
        
        layout.addLayout(av_row)
        
        # Logs
        layout.addWidget(QLabel("<b>Logs</b>"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("background:#000; color:#0f0;")
        layout.addWidget(self.txt_log, stretch=1)
        
        self.tabs.addTab(tab, "System")
    
    # ========== Event Handlers ==========
    
    def write_log(self, msg: str) -> None:
        """Write message to log panel."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.txt_log.append(f"[{timestamp}] {msg}")
        except Exception:
            pass
        logger.info(msg)
    
    def on_file_served(self, name: str) -> None:
        """Handle file served event."""
        self.served_count += 1
        self.lbl_served.setText(f"Files served: {self.served_count}")
        self.write_log(f"Served: {mask_name(name)}")
    
    def choose_dest(self) -> None:
        """Select destination folder dialog."""
        folder = QFileDialog.getExistingDirectory(
            self, 
            "Select iRacing/setups folder"
        )
        if folder:
            SETTINGS["save_dir"] = folder
            save_settings()
            self.lbl_dest.setText(folder)
            self.write_log(f"Destination folder set: {folder}")
    
    def choose_origin(self) -> None:
        """Select outgoing folder dialog."""
        folder = QFileDialog.getExistingDirectory(
            self, 
            "Select outgoing folder"
        )
        if folder:
            global SWARM_FOLDER
            SWARM_FOLDER = folder
            SETTINGS["share_dir"] = folder
            save_settings()
            self.lbl_orig.setText(os.path.basename(folder))
            self.write_log(f"Outgoing folder set: {folder}")
    
    def locate_tor(self) -> None:
        """Locate Tor executable dialog."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Locate tor.exe",
            "",
            "Executables (*.exe);;All Files (*)"
        )
        if file_path:
            self.input_tor.setText(file_path)
            SETTINGS["tor_path"] = file_path
            save_settings()
            self.write_log("Tor path saved")
    
    def save_rules(self) -> None:
        """Save DLP rules to file."""
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                f.write(self.txt_rules.toPlainText())
            dlp_manager.load_rules()
            self.write_log("DLP rules saved")
        except Exception:
            self.write_log("Failed to save DLP rules")
    
    def load_settings(self) -> None:
        """Load saved settings into UI."""
        # Peers
        if os.path.exists(PEERS_FILE):
            try:
                with open(PEERS_FILE, "r", encoding="utf-8") as f:
                    self.txt_peers.setPlainText(f.read())
            except Exception:
                pass
        
        # DLP rules
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    self.txt_rules.setPlainText(f.read())
            except Exception:
                pass
        
        # Settings
        try:
            tor_path = SETTINGS.get("tor_path", "")
            if tor_path:
                self.input_tor.setText(tor_path)
            
            dl_kb = SETTINGS.get("download_limit_bps", DEFAULT_DOWNLOAD_LIMIT_BPS) // 1024
            ul_kb = SETTINGS.get("upload_limit_bps", DEFAULT_UPLOAD_LIMIT_BPS) // 1024
            
            self.input_dl.setText(str(int(dl_kb)))
            self.input_ul.setText(str(int(ul_kb)))
            
            self.chk_force_av.setChecked(
                SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT)
            )
            
            # Folders
            if SETTINGS.get("share_dir"):
                global SWARM_FOLDER
                SWARM_FOLDER = SETTINGS.get("share_dir")
                self.lbl_orig.setText(os.path.basename(SWARM_FOLDER))
            
            if SETTINGS.get("save_dir"):
                self.lbl_dest.setText(SETTINGS.get("save_dir"))
            
            # Sync mode
            if SETTINGS.get("team_folder"):
                self.txt_team.setText(SETTINGS.get("team_folder"))
            
            if SETTINGS.get("sync_mode") == 3:
                self.rb_smart.setChecked(True)
            else:
                self.rb_folder.setChecked(True)
            
            # Tor mode
            use_embedded = SETTINGS.get("use_embedded_tor", True)
            self.chk_embedded_tor.setChecked(bool(use_embedded))
            self.input_tor.setEnabled(not use_embedded)
            self.btn_locate_tor.setEnabled(not use_embedded)
        
        except Exception:
            pass
    
    def on_tor_mode_changed(self) -> None:
        """Handle Tor mode checkbox change."""
        use_embedded = self.chk_embedded_tor.isChecked()
        SETTINGS["use_embedded_tor"] = bool(use_embedded)
        save_settings()
        
        self.input_tor.setEnabled(not use_embedded)
        self.btn_locate_tor.setEnabled(not use_embedded)
        
        self.write_log(f"Tor mode: {'embedded' if use_embedded else 'external'}")
    
    def toggle_server(self) -> None:
        """Start or stop Tor and Flask server."""
        if self.tor_worker and self.tor_worker.isRunning():
            self.write_log("Server already running")
            return
        
        use_embedded = SETTINGS.get("use_embedded_tor", True)
        
        if use_embedded:
            # Resolve embedded Tor path
            try:
                if getattr(sys, "frozen", False):
                    base = Path(sys.argv[0]).resolve().parent
                else:
                    base = Path(__file__).resolve().parent
            except Exception:
                base = Path(__file__).resolve().parent
            
            tor_exe = "tor.exe" if sys.platform.startswith("win") else "tor"
            embedded_path = base / "tor" / tor_exe
            
            if not embedded_path.exists():
                QMessageBox.critical(
                    self,
                    "Embedded Tor Missing",
                    f"Embedded tor not found at:\n{embedded_path}\n\n"
                    "Place the tor/ folder next to the program or use external Tor."
                )
                return
            
            tor_path = str(embedded_path)
        else:
            # Use external Tor
            tor_path = self.input_tor.text().strip() or SETTINGS.get("tor_path", "")
            if not tor_path or not os.path.exists(tor_path):
                QMessageBox.critical(
                    self,
                    "Tor Missing",
                    "External tor.exe not found. Please specify the path."
                )
                return
            
            SETTINGS["tor_path"] = tor_path
            save_settings()
        
        SETTINGS["use_embedded_tor"] = use_embedded
        save_settings()
        
        # Start Tor worker
        self.tor_worker = TorManagerWorker(tor_path)
        self.tor_worker.status_update.connect(self.write_log)
        self.tor_worker.onion_ready.connect(self.on_onion_ready)
        self.tor_worker.identity_reset.connect(
            lambda: QMessageBox.information(self, "Identity", "Identity regenerated")
        )
        
        self.lbl_global_status.setText("STARTING TOR SERVER…")
        self.lbl_global_status.setStyleSheet(
            "background:#FFA000; color:#000; padding:8px; "
            "font-weight:bold; border-radius:6px;"
        )
        
        self.tor_worker.start()
        self.write_log("Starting Tor...")
    
    def on_onion_ready(self, onion: str) -> None:
        """Handle onion service ready event."""
        self.txt_my_link.setText(onion)
        self.lbl_global_status.setText("ONLINE - TOR CONNECTED")
        self.lbl_global_status.setStyleSheet(
            "background:#2E7D32; color:#fff; padding:8px; border-radius:6px;"
        )
        self.write_log(f"Onion ready: {onion}")
    
    def toggle_sync(self) -> None:
        """Start or stop continuous sync."""
        if self.sync_worker and self.sync_worker.isRunning():
            self.sync_worker.stop()
            self.btn_sync.setText("START SYNC")
            self.write_log("Stopping sync...")
            return
        
        # Apply and save settings
        try:
            dl_kb = max(0, int(self.input_dl.text().strip()))
            ul_kb = max(0, int(self.input_ul.text().strip()))
            
            SETTINGS["download_limit_bps"] = dl_kb * 1024
            SETTINGS["upload_limit_bps"] = ul_kb * 1024
            SETTINGS["force_av_scan"] = self.chk_force_av.isChecked()
            
            peers = [
                line.strip() 
                for line in self.txt_peers.toPlainText().splitlines() 
                if line.strip()
            ]
            SETTINGS["peers"] = peers
            
            SETTINGS["sync_mode"] = 3 if self.rb_smart.isChecked() else 2
            SETTINGS["team_folder"] = self.txt_team.text().strip() or "Team_Setups"
            
            save_settings()
        except Exception:
            self.write_log("Error applying limits")
        
        # Save peers to file
        try:
            with open(PEERS_FILE, "w", encoding="utf-8") as f:
                f.write(self.txt_peers.toPlainText())
        except Exception:
            pass
        
        # Validate configuration
        dest = SETTINGS.get("save_dir") or self.lbl_dest.text().strip()
        if not dest:
            QMessageBox.warning(
                self,
                "Missing Destination",
                "Please select a destination folder first."
            )
            return
        
        peers = SETTINGS.get("peers", [])
        if not peers:
            QMessageBox.warning(
                self,
                "Missing Peers",
                "Please add at least one peer .onion URL."
            )
            return
        
        # Start sync worker
        team_name = self.txt_team.text().strip() or "Team_Setups"
        sync_mode = 3 if self.rb_smart.isChecked() else 2
        force_av = SETTINGS.get("force_av_scan", FORCE_AV_SCAN_DEFAULT)
        
        self.sync_worker = SwarmSyncWorker(
            peers,
            dest,
            team_name,
            sync_mode,
            only_sto=True,
            scan_virus=force_av
        )
        
        self.sync_worker.log.connect(self.write_log)
        self.sync_worker.finished_cycle.connect(lambda s: self.write_log(s))
        self.sync_worker.progress_update.connect(
            lambda pct, txt: (self.progress.setValue(pct), self.write_log(txt))
        )
        self.sync_worker.security_warning.connect(
            lambda m: QMessageBox.critical(self, "SECURITY ALERT", m)
        )
        
        self.sync_worker.start()
        self.btn_sync.setText("STOP SYNC")
        self.write_log("Continuous sync started")
    
    def burn_identity(self) -> None:
        """Remove saved onion identity (generates new .onion on next start)."""
        if os.path.exists(KEY_FILE):
            try:
                shutil.copyfile(KEY_FILE, KEY_FILE_BAK)
            except Exception:
                pass
            
            try:
                os.remove(KEY_FILE)
            except Exception:
                pass
        
        QMessageBox.information(
            self,
            "Identity Removed",
            "Saved identity removed. Start the server to create a new one."
        )
        self.write_log("User removed identity")
        
        # Stop Tor if running
        try:
            if self.tor_worker:
                self.tor_worker.terminate_tor()
        except Exception:
            pass
    
    def generate_one_time_token(self) -> None:
        """Generate ephemeral one-time access token."""
        try:
            ttl_min = max(1, int(self.input_token_ttl.text().strip()))
        except Exception:
            ttl_min = ONE_TIME_TOKEN_TTL_DEFAULT // 60
        
        note = self.input_token_note.text().strip() or "shared_manually"
        expires = time.time() + ttl_min * 60
        token = secrets.token_urlsafe(28)
        
        # Bind to current snapshot if folder available
        bound_map_id = None
        
        if SWARM_FOLDER and os.path.exists(SWARM_FOLDER):
            dlp_manager.load_rules()
            virtual_map = {}
            files_data = []
            
            for root, dirs, files in os.walk(SWARM_FOLDER):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    
                    if not is_within_directory(SWARM_FOLDER, full_path):
                        continue
                    
                    rel_path = os.path.relpath(full_path, SWARM_FOLDER)
                    rel_path = rel_path.replace("\\", "/")
                    
                    fake = dlp_manager.make_fake_name(rel_path, ADMIN_KEY_BYTES)
                    
                    try:
                        stat = os.stat(full_path)
                        age_hours = int((time.time() - stat.st_mtime) // 3600)
                        size = stat.st_size
                    except Exception:
                        age_hours = -1
                        size = -1
                    
                    files_data.append({
                        "path": fake,
                        "size": size,
                        "age_hours": age_hours
                    })
                    virtual_map[fake] = full_path
            
            map_json = json.dumps(
                files_data,
                separators=(",", ":"),
                ensure_ascii=False
            ).encode("utf-8")
            
            sig = hmac.new(
                ADMIN_KEY_BYTES,
                map_json,
                hashlib.sha256
            ).hexdigest()
            
            map_id = secrets.token_hex(8)
            map_token = secrets.token_urlsafe(24)
            
            _EPHEMERAL_MAPS[map_id] = {
                "map": virtual_map,
                "sig": sig,
                "token": map_token,
                "ts": time.time()
            }
            
            bound_map_id = map_id
        
        # Store token
        _ONE_TIME_TOKENS[token] = {
            "type": "oneoff",
            "map_id": bound_map_id,
            "expires": expires,
            "note": note
        }
        
        self.input_generated_token.setText(token)
        self.write_log(
            f"Generated one-time token (ttl {ttl_min}min) "
            f"bound_map={bound_map_id} note={note}"
        )
        
        # Log to file
        try:
            token_log = os.path.join(CONFIG_DIR, "one_time_token_log.jsonl")
            with open(token_log, "a", encoding="utf-8") as f:
                log_entry = {
                    "ts": int(time.time()),
                    "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                    "expires": int(expires),
                    "note": note,
                    "bound_map": bound_map_id
                }
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass
    
    def copy_generated_token(self) -> None:
        """Copy generated token to clipboard."""
        token = self.input_generated_token.text().strip()
        
        if not token:
            QMessageBox.information(self, "Token", "No token generated")
            return
        
        clipboard = QApplication.clipboard()
        clipboard.setText(token)
        QMessageBox.information(self, "Copied", "Token copied to clipboard")
    
    def closeEvent(self, event) -> None:
        """Handle application close event."""
        try:
            # Stop sync worker
            if self.sync_worker and self.sync_worker.isRunning():
                self.sync_worker.stop()
                time.sleep(0.2)
            
            # Terminate Tor
            if self.tor_worker:
                try:
                    self.tor_worker.terminate_tor()
                except Exception:
                    pass
        except Exception:
            pass
        
        event.accept()


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

def main():
    """Application entry point."""
    app_qt = QApplication(sys.argv)
    
    # Set application metadata
    app_qt.setApplicationName(APP_NAME)
    app_qt.setApplicationVersion(APP_VERSION)
    
    # Create and show main window
    window = MainAppWindow()
    window.show()
    
    # Initialize upload throttle
    ensure_global_upload_bucket()
    
    # Start Qt event loop
    sys.exit(app_qt.exec())


if __name__ == "__main__":
    main()
