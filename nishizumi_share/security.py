"""Path safety, filename sanitisation and DLP name mapping.

The server never exposes real paths.  Each shared file gets a *public name*:
a sanitised version of its relative path plus a short HMAC suffix keyed by a
per-install secret.  Clients strip the suffix when writing to disk, so the
suffix is purely an opaque, collision-resistant handle for the server side.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from pathlib import Path
from typing import Dict, Optional

from .config import Paths, atomic_write_text, get_paths

# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

#: Windows device names that must never be used as a path component.
_RESERVED_WINDOWS_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

_UNSAFE_CHARS_RE = re.compile(r'[\x00-\x1f\x7f<>:"|?*\\/]')

HMAC_SUFFIX_LENGTH = 16
HMAC_SUFFIX_RE = re.compile(r"__(?P<digest>[0-9a-f]{%d})$" % HMAC_SUFFIX_LENGTH, re.IGNORECASE)


def is_within_directory(base_dir: str | os.PathLike, target_path: str | os.PathLike) -> bool:
    """Return True when ``target_path`` resolves inside ``base_dir``.

    Both paths are fully resolved first, so symlinks that point outside the
    base directory are rejected rather than followed.
    """
    try:
        base = Path(base_dir).resolve(strict=False)
        target = Path(target_path).resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        return False

    if base == target:
        return True
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def safe_join(base_dir: str | os.PathLike, *relative_parts: str) -> Optional[Path]:
    """Join user-controlled components onto ``base_dir``, or return None.

    Returns ``None`` when the result would escape ``base_dir`` — including via
    ``..``, absolute components, or a symlinked parent.
    """
    base = Path(base_dir)
    cleaned = []

    for part in relative_parts:
        raw = str(part)
        # Reject absolute inputs before splitting: after the split on "/" no
        # single element still looks absolute, so the check has to happen here.
        if os.path.isabs(raw) or raw.startswith(("/", "\\")):
            return None
        if len(raw) >= 2 and raw[1] == ":":  # Windows drive letter
            return None

        for element in raw.replace("\\", "/").split("/"):
            element = element.strip()
            if not element or element == ".":
                continue
            if element == "..":
                return None
            cleaned.append(element)

    if not cleaned:
        return None

    candidate = base.joinpath(*cleaned)
    if not is_within_directory(base, candidate):
        return None
    return candidate


def sanitize_component(component: str, *, max_length: int = 120) -> str:
    """Reduce one path component to something safe on every platform."""
    text = unicodedata.normalize("NFKC", str(component))
    text = _UNSAFE_CHARS_RE.sub("_", text)
    text = text.replace("..", "_")
    text = text.strip(" .")

    if not text:
        return "_"

    stem = text.split(".")[0].lower()
    if stem in _RESERVED_WINDOWS_NAMES:
        text = f"_{text}"

    if len(text) > max_length:
        # Preserve the extension when truncating so files stay openable.
        root, ext = os.path.splitext(text)
        keep = max(1, max_length - len(ext))
        text = root[:keep] + ext

    return text or "_"


def mask_name(name: str) -> str:
    """Partially redact a filename so logs do not leak full names."""
    text = str(name)
    if len(text) <= 8:
        return "****" + text[-2:]
    return f"{text[:3]}...{text[-3:]}"


# ---------------------------------------------------------------------------
# Naming key
# ---------------------------------------------------------------------------


def load_or_create_name_key(paths: Optional[Paths] = None) -> bytes:
    """Return the per-install HMAC key used to build public file names.

    The key only needs to be stable and secret; it is regenerated (and the
    public names change) if the file is deleted.
    """
    paths = paths or get_paths()
    key_file = paths.name_key

    if key_file.exists():
        try:
            existing = key_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing.encode("utf-8")
        except OSError:
            pass

    key = secrets.token_urlsafe(48)
    try:
        atomic_write_text(key_file, key)
    except OSError:
        # An unwritable config dir should not stop the app; names simply will
        # not be stable across restarts.
        pass
    return key.encode("utf-8")


# ---------------------------------------------------------------------------
# Public name mapping
# ---------------------------------------------------------------------------


class NameMapper:
    """Builds and reverses the public names used on the wire."""

    def __init__(self, key: bytes, rules: Optional[Dict[str, str]] = None):
        self.key = key
        self.rules: Dict[str, str] = dict(rules or {})

    def set_rules(self, rules: Dict[str, str]) -> None:
        self.rules = dict(rules)

    def apply_rules(self, text: str) -> str:
        """Apply DLP substitutions case-insensitively, replacing every match."""
        result = text
        for private_term, public_code in self.rules.items():
            if not private_term:
                continue
            result = re.sub(re.escape(private_term), public_code, result, flags=re.IGNORECASE)
        return result

    def public_name(self, rel_path: str) -> str:
        """Map a relative path to its public, HMAC-suffixed equivalent."""
        normalised = str(rel_path).replace("\\", "/").strip("/")
        parts = [part for part in normalised.split("/") if part not in ("", ".")]
        sanitized = [sanitize_component(self.apply_rules(part)) for part in parts]
        public_path = "/".join(sanitized) or "_"

        digest = hmac.new(self.key, normalised.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{public_path}__{digest[:HMAC_SUFFIX_LENGTH]}"


def strip_hmac_suffix(public_path: str) -> str:
    """Remove the ``__<16 hex>`` suffix from the final component of a path."""
    text = str(public_path).replace("\\", "/")
    parts = text.split("/")
    if not parts:
        return text

    match = HMAC_SUFFIX_RE.search(parts[-1])
    if match:
        stripped = parts[-1][: match.start()]
        # Never return an empty basename — keep the original if stripping would
        # leave nothing behind.
        if stripped:
            parts[-1] = stripped
    return "/".join(parts)


# ---------------------------------------------------------------------------
# DLP rules file
# ---------------------------------------------------------------------------


def parse_dlp_rules(text: str) -> Dict[str, str]:
    """Parse ``private=PUBLIC`` rules, one per line, ``#`` for comments."""
    rules: Dict[str, str] = {}
    for line in str(text).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key:
            rules[key] = value
    return rules


def load_dlp_rules(paths: Optional[Paths] = None) -> Dict[str, str]:
    paths = paths or get_paths()
    if not paths.dlp_rules.exists():
        return {}
    try:
        return parse_dlp_rules(paths.dlp_rules.read_text(encoding="utf-8"))
    except OSError:
        return {}


def save_dlp_rules(text: str, paths: Optional[Paths] = None) -> bool:
    paths = paths or get_paths()
    try:
        atomic_write_text(paths.dlp_rules, text)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def tokens_equal(left: str, right: str) -> bool:
    """Constant-time token comparison that tolerates non-ASCII input."""
    if not left or not right:
        return False
    return hmac.compare_digest(str(left).encode("utf-8"), str(right).encode("utf-8"))


def hash_token(token: str) -> str:
    """Hash a token for audit logging (never log the token itself)."""
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def sha256_file(path: str | os.PathLike, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
