# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build definition.

Produces a one-folder build under ``dist/NishizumiShare``.  One-folder (rather
than one-file) keeps start-up fast, avoids the temp-extraction pattern that
trips antivirus heuristics, and lets the installer patch individual files on
update.
"""

import os
from pathlib import Path

SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent

# The Tor Expert Bundle is fetched by packaging/fetch_tor.py before building.
TOR_DIR = SPEC_DIR / "tor"
ICON_FILE = SPEC_DIR / "app.ico"

datas = []
if TOR_DIR.is_dir():
    datas.append((str(TOR_DIR), "tor"))
else:
    print("WARNING: packaging/tor not found — the build will have no bundled Tor")

a = Analysis(
    [str(SPEC_DIR / "entrypoint.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "socks",              # PySocks, imported indirectly by requests
        "waitress",
        "nishizumi_share.ui",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # Trim the bundle: none of these are used by the app.
        "tkinter", "unittest", "pydoc", "doctest",
        "PyQt6.QtQml", "PyQt6.QtQuick", "PyQt6.QtWebEngineCore",
        "PyQt6.Qt3DCore", "PyQt6.QtMultimedia", "PyQt6.QtBluetooth",
        "numpy", "pandas", "matplotlib",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NishizumiShare",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # GUI application: no console window
    icon=str(ICON_FILE) if ICON_FILE.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="NishizumiShare",
)
