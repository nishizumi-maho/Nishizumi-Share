"""PyInstaller entry point.

Kept as a separate module because PyInstaller needs a plain script, not a
``-m`` package invocation.
"""

import multiprocessing
import sys

from nishizumi_share.__main__ import main

if __name__ == "__main__":
    # Required so a frozen build does not re-launch the GUI in child processes.
    multiprocessing.freeze_support()
    sys.exit(main())
