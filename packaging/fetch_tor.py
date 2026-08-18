#!/usr/bin/env python3
"""Download and verify the Tor Expert Bundle for packaging.

The bundle is never committed to the repository; the build fetches it and
checks it against the checksum file the Tor Project publishes next to it.
A mismatch aborts the build rather than shipping an unverified binary.

Usage:
    python packaging/fetch_tor.py [--version 14.5.8] [--dest packaging/tor]
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

#: Fallback if version discovery fails. dist.torproject.org only keeps the
#: current release, so anything pinned here goes stale; the archive mirror is
#: tried as well, which is where older versions live.
FALLBACK_VERSION = "15.0.20"

DIST_BASE = "https://dist.torproject.org/torbrowser"
ARCHIVE_BASE = "https://archive.torproject.org/tor-package-archive/torbrowser"
MIRRORS = (DIST_BASE, ARCHIVE_BASE)

CHECKSUM_FILE = "sha256sums-unsigned-build.txt"
NETWORK_TIMEOUT = 120

_VERSION_DIR_RE = re.compile(r'href="(\d+\.\d+(?:\.\d+)?)/"')


def bundle_name(version: str, platform: str) -> str:
    return f"tor-expert-bundle-{platform}-{version}.tar.gz"


def version_key(version: str) -> tuple:
    return tuple(int(part) for part in version.split("."))


def discover_latest_version() -> str:
    """Read the newest Tor Browser version from the dist index.

    Falls back to :data:`FALLBACK_VERSION` when the index cannot be read, so
    an offline or reshuffled mirror does not hard-fail the build here — the
    checksum step still guarantees integrity either way.
    """
    try:
        index = fetch_text(f"{DIST_BASE}/")
    except Exception as exc:
        print(f"  version discovery failed ({exc}); using {FALLBACK_VERSION}")
        return FALLBACK_VERSION

    versions = _VERSION_DIR_RE.findall(index)
    if not versions:
        print(f"  no versions found in the index; using {FALLBACK_VERSION}")
        return FALLBACK_VERSION

    latest = max(set(versions), key=version_key)
    print(f"  discovered latest version: {latest}")
    return latest


def resolve_mirror(version: str) -> str:
    """Return the first mirror that serves ``version``."""
    for base in MIRRORS:
        url = f"{base}/{version}/{CHECKSUM_FILE}"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "nishizumi-share-build"})
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status == 200:
                    print(f"  using mirror {base}")
                    return base
        except Exception:
            continue
    raise SystemExit(f"Tor {version} was not found on any known mirror")


def download(url: str, destination: Path) -> None:
    print(f"  fetching {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "nishizumi-share-build"})
    with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT) as response:
        if response.status != 200:
            raise SystemExit(f"Download failed: HTTP {response.status} for {url}")
        with open(destination, "wb") as handle:
            shutil.copyfileobj(response, handle)


def fetch_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "nishizumi-share-build"})
    with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")


def expected_digest(checksums: str, filename: str) -> str:
    for line in checksums.splitlines():
        parts = line.split()
        if len(parts) >= 2 and Path(parts[-1].lstrip("*")).name == filename:
            return parts[0].strip().lower()
    raise SystemExit(f"{filename} is not listed in {CHECKSUM_FILE}")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract(archive: Path, destination: Path) -> None:
    """Extract the archive, refusing any member that escapes ``destination``."""
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            target = (root / member.name).resolve()
            if root != target and root not in target.parents:
                raise SystemExit(f"Refusing unsafe archive member: {member.name}")
            if member.issym() or member.islnk():
                raise SystemExit(f"Refusing link member: {member.name}")
        tar.extractall(destination)


def flatten(destination: Path) -> None:
    """Move the tor binaries to the top level of ``destination``.

    The expert bundle nests them under ``tor/``; the app looks in both places,
    but a flat layout keeps the installed tree tidy.
    """
    nested = destination / "tor"
    if not nested.is_dir():
        return

    for entry in nested.iterdir():
        target = destination / entry.name
        if target.exists():
            continue
        shutil.move(str(entry), str(target))

    try:
        nested.rmdir()
    except OSError:
        pass  # Leftover files are harmless.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        default="",
        help="specific Tor Browser version; omit to use the newest available",
    )
    parser.add_argument("--dest", default="packaging/tor", type=Path)
    parser.add_argument(
        "--platform",
        default="windows-x86_64",
        choices=["windows-x86_64", "windows-i686", "linux-x86_64", "macos-x86_64"],
    )
    args = parser.parse_args()

    destination = Path(args.dest)
    if destination.exists():
        print(f"Removing existing {destination}")
        shutil.rmtree(destination)

    print("Resolving Tor Expert Bundle")
    version = args.version or discover_latest_version()
    mirror = resolve_mirror(version)

    archive_name = bundle_name(version, args.platform)
    base_url = f"{mirror}/{version}"

    print(f"Tor Expert Bundle {version} ({args.platform})")

    checksums = fetch_text(f"{base_url}/{CHECKSUM_FILE}")
    wanted = expected_digest(checksums, archive_name)

    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / archive_name
        download(f"{base_url}/{archive_name}", archive)

        actual = sha256_of(archive)
        if actual != wanted:
            raise SystemExit(
                f"Checksum mismatch for {archive_name}\n  expected {wanted}\n  got      {actual}"
            )
        print(f"  checksum OK ({wanted[:16]}…)")

        safe_extract(archive, destination)

    flatten(destination)

    binaries = [p.name for p in destination.iterdir() if p.is_file()]
    print(f"  extracted to {destination}: {', '.join(sorted(binaries)[:6])}")

    tor_exe = destination / ("tor.exe" if "windows" in args.platform else "tor")
    if not tor_exe.exists():
        raise SystemExit(f"Expected {tor_exe} in the extracted bundle")

    if "windows" not in args.platform:
        tor_exe.chmod(0o755)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
