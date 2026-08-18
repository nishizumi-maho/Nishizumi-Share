"""Entry point: ``python -m nishizumi_share``."""

from __future__ import annotations

import argparse
import sys

from . import DISPLAY_NAME, __version__


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="nishizumi-share",
        description=f"{DISPLAY_NAME} — anonymous file sharing over Tor hidden services",
    )
    parser.add_argument("--version", action="version", version=f"{DISPLAY_NAME} {__version__}")
    parser.add_argument(
        "--check-updates",
        action="store_true",
        help="check for a newer release and exit",
    )
    parser.add_argument(
        "--config-dir",
        metavar="PATH",
        help="use an alternative configuration directory",
    )
    args, qt_argv = parser.parse_known_args(argv if argv is not None else sys.argv[1:])

    if args.config_dir:
        from .config import set_config_root

        set_config_root(args.config_dir)

    if args.check_updates:
        return _check_updates()

    from .ui import run

    return run([sys.argv[0], *qt_argv])


def _check_updates() -> int:
    from .logging_setup import configure_logging
    from .updater import UpdateError, Updater

    configure_logging()
    try:
        info = Updater().check()
    except UpdateError as exc:
        print(f"Update check failed: {exc}", file=sys.stderr)
        return 2

    if info is None:
        print(f"{DISPLAY_NAME} {__version__} is up to date.")
        return 0

    print(f"Update available: {info.version} ({info.html_url})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
