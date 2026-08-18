"""Nishizumi Share — secure, anonymous file sharing over Tor hidden services.

The package is split so that everything except :mod:`nishizumi_share.ui` is
importable without Qt.  That keeps the network/security core unit-testable on
headless machines and keeps the GUI a thin layer on top of it.
"""

from __future__ import annotations

__version__ = "3.0.0"

APP_NAME = "NishizumiShare"
DISPLAY_NAME = "Nishizumi Share"
GITHUB_REPO = "nishizumi-maho/Nishizumi-Share"

__all__ = ["__version__", "APP_NAME", "DISPLAY_NAME", "GITHUB_REPO"]
