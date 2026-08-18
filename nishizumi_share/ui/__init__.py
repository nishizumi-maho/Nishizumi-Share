"""Qt user interface.

Importing this package pulls in PyQt6; the rest of :mod:`nishizumi_share`
deliberately does not, so the core stays usable headless.
"""

from .main_window import MainWindow, run

__all__ = ["MainWindow", "run"]
