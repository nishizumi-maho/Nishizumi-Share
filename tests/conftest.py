"""Shared fixtures.

Every test gets an isolated config root so nothing touches the developer's
real settings.
"""

from __future__ import annotations

import pytest

from nishizumi_share.config import Settings, set_config_root


@pytest.fixture()
def paths(tmp_path, monkeypatch):
    monkeypatch.setenv("NISHIZUMI_CONFIG_DIR", str(tmp_path / "config"))
    return set_config_root(tmp_path / "config")


@pytest.fixture()
def settings(paths) -> Settings:
    return Settings.load(paths)


@pytest.fixture()
def share_dir(tmp_path):
    """A populated directory to serve."""
    root = tmp_path / "share"
    (root / "ferrari296gt3").mkdir(parents=True)
    (root / "ferrari296gt3" / "monza_qualy.sto").write_bytes(b"setup-data" * 100)
    (root / "ferrari296gt3" / "notes.txt").write_bytes(b"hello")
    (root / "readme.md").write_bytes(b"top level")
    return root
