"""Settings validation and migration."""

from __future__ import annotations

import json

from nishizumi_share.config import (
    DEFAULT_SETTINGS,
    Settings,
    _safe_folder_name,
    atomic_write_text,
    normalise,
)


def test_defaults_are_complete():
    result = normalise({})
    assert set(result) == set(DEFAULT_SETTINGS)


def test_unknown_keys_are_dropped():
    assert "bogus" not in normalise({"bogus": 1})


class TestMigration:
    def test_use_embedded_tor_becomes_tor_mode(self):
        assert normalise({"use_embedded_tor": False})["tor_mode"] == "external"
        assert normalise({"use_embedded_tor": True})["tor_mode"] == "embedded"

    def test_numeric_sync_mode(self):
        assert normalise({"sync_mode": 3})["sync_mode"] == "smart"
        assert normalise({"sync_mode": 2})["sync_mode"] == "mirror"
        assert normalise({"sync_mode": "3"})["sync_mode"] == "smart"

    def test_force_av_scan_preference_is_kept(self):
        # v2 stored the preference but a global kill switch ignored it.
        assert normalise({"force_av_scan": True})["av_enabled"] is True

    def test_external_tor_path_is_renamed(self):
        assert normalise({"external_tor_path": "/usr/bin/tor"})["tor_path"] == "/usr/bin/tor"

    def test_legacy_team_and_autostart_keys(self):
        result = normalise({"team_name": "Alpha", "start_with_windows": True})
        assert result["team_folder"] == "Alpha"
        assert result["start_with_system"] is True


class TestValidation:
    def test_string_numbers_are_coerced(self):
        assert normalise({"download_limit_bps": "4096"})["download_limit_bps"] == 4096

    def test_garbage_falls_back_to_default(self):
        result = normalise({"download_limit_bps": "fast", "socks_port": "abc"})
        assert result["download_limit_bps"] == DEFAULT_SETTINGS["download_limit_bps"]
        assert result["socks_port"] == DEFAULT_SETTINGS["socks_port"]

    def test_ports_are_clamped(self):
        assert normalise({"socks_port": 99999})["socks_port"] == 65535
        assert normalise({"socks_port": -5})["socks_port"] == 1

    def test_max_file_size_is_capped(self):
        assert normalise({"max_file_size": 10**15})["max_file_size"] < 10**15

    def test_invalid_enum_falls_back(self):
        assert normalise({"tor_mode": "carrier-pigeon"})["tor_mode"] == "embedded"
        assert normalise({"sync_mode": "sideways"})["sync_mode"] == "smart"

    def test_peers_are_deduplicated_and_trimmed(self):
        peers = normalise({"peers": [" a.onion ", "a.onion", "", "b.onion"]})["peers"]
        assert peers == ["a.onion", "b.onion"]

    def test_peers_accept_newline_separated_string(self):
        assert normalise({"peers": "a.onion\nb.onion"})["peers"] == ["a.onion", "b.onion"]

    def test_booleans_accept_legacy_strings(self):
        assert normalise({"av_enabled": "yes"})["av_enabled"] is True
        assert normalise({"av_enabled": "off"})["av_enabled"] is False


class TestSafeFolderName:
    def test_traversal_is_rejected(self):
        assert _safe_folder_name("../../etc", "F") == "etc"
        assert _safe_folder_name("..", "F") == "F"

    def test_separators_are_stripped(self):
        assert _safe_folder_name("a/b/c", "F") == "c"
        assert _safe_folder_name("a\\b", "F") == "b"

    def test_empty_falls_back(self):
        assert _safe_folder_name("   ", "F") == "F"
        assert _safe_folder_name(None, "F") == "F"

    def test_illegal_characters_replaced(self):
        assert "<" not in _safe_folder_name("te<am", "F")


class TestPersistence:
    def test_round_trip(self, paths):
        settings = Settings.load(paths)
        settings.set("team_folder", "Scuderia")
        assert settings.save()

        reloaded = Settings.load(paths)
        assert reloaded.get("team_folder") == "Scuderia"

    def test_corrupt_file_falls_back_to_defaults(self, paths):
        paths.settings.write_text("{not json", encoding="utf-8")
        settings = Settings.load(paths)
        assert settings.get("team_folder") == DEFAULT_SETTINGS["team_folder"]

    def test_saved_file_is_valid_json(self, paths):
        Settings.load(paths).save()
        assert isinstance(json.loads(paths.settings.read_text(encoding="utf-8")), dict)

    def test_atomic_write_leaves_no_temp_files(self, tmp_path):
        target = tmp_path / "x.json"
        atomic_write_text(target, "hello")
        assert target.read_text() == "hello"
        assert list(tmp_path.iterdir()) == [target]
