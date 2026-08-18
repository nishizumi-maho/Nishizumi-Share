"""Version comparison, release selection and checksum verification."""

from __future__ import annotations

import hashlib

import pytest

from nishizumi_share.updater import (
    UpdateError,
    Updater,
    _release_to_update,
    is_newer,
    parse_checksums,
    parse_version,
)


class TestParseVersion:
    @pytest.mark.parametrize("value", ["3.0.0", "v3.0.0", " 3.0.0 ", "3.0", "3"])
    def test_accepted_forms(self, value):
        assert parse_version(value) is not None

    @pytest.mark.parametrize("value", ["", "abc", "v", None, "3.x.0", "..", "v-"])
    def test_rejected_forms(self, value):
        assert parse_version(value) is None

    def test_v_prefix_is_equivalent(self):
        assert parse_version("v3.0.0") == parse_version("3.0.0")


class TestIsNewer:
    @pytest.mark.parametrize(
        "candidate,current",
        [("3.0.1", "3.0.0"), ("3.1.0", "3.0.9"), ("4.0.0", "3.9.9"), ("v3.0.1", "3.0.0")],
    )
    def test_newer(self, candidate, current):
        assert is_newer(candidate, current)

    @pytest.mark.parametrize(
        "candidate,current",
        [("3.0.0", "3.0.0"), ("2.9.9", "3.0.0"), ("3.0.0", "3.0.1")],
    )
    def test_not_newer(self, candidate, current):
        assert not is_newer(candidate, current)

    def test_release_beats_its_own_prerelease(self):
        assert is_newer("3.0.0", "3.0.0-rc1")
        assert not is_newer("3.0.0-rc1", "3.0.0")

    def test_prerelease_ordering(self):
        assert is_newer("3.0.0-rc2", "3.0.0-rc1")

    def test_unparseable_never_newer(self):
        assert not is_newer("banana", "3.0.0")
        assert not is_newer("3.0.0", "banana")


class TestParseChecksums:
    def test_standard_format(self):
        digest = "a" * 64
        assert parse_checksums(f"{digest}  Setup.exe") == {"Setup.exe": digest}

    def test_binary_marker_is_stripped(self):
        digest = "b" * 64
        assert parse_checksums(f"{digest} *Setup.exe") == {"Setup.exe": digest}

    def test_paths_are_reduced_to_basename(self):
        digest = "c" * 64
        assert parse_checksums(f"{digest}  dist/Setup.exe") == {"Setup.exe": digest}

    def test_invalid_lines_ignored(self):
        assert parse_checksums("# comment\n\nnothex  Setup.exe\nshort") == {}


class TestReleaseSelection:
    def _release(self, tag="v3.1.0", assets=None):
        return {
            "tag_name": tag,
            "body": "notes",
            "html_url": "https://example/releases/tag",
            "assets": assets or [],
        }

    def test_tag_becomes_version(self):
        assert _release_to_update(self._release()).version == "3.1.0"

    def test_tag_without_v_prefix(self):
        assert _release_to_update(self._release(tag="3.1.0")).version == "3.1.0"

    def test_untagged_release_is_ignored(self):
        assert _release_to_update({"tag_name": ""}) is None

    def test_installer_asset_is_picked(self, monkeypatch):
        monkeypatch.setattr("nishizumi_share.updater.sys.platform", "win32")
        info = _release_to_update(
            self._release(assets=[
                {"name": "notes.txt", "browser_download_url": "u1", "size": 1},
                {"name": "NishizumiShare-Setup-3.1.0.exe", "browser_download_url": "u2", "size": 99},
            ])
        )
        assert info.asset_name == "NishizumiShare-Setup-3.1.0.exe"
        assert info.asset_size == 99

    def test_checksum_asset_is_found(self, monkeypatch):
        monkeypatch.setattr("nishizumi_share.updater.sys.platform", "win32")
        info = _release_to_update(
            self._release(assets=[
                {"name": "NishizumiShare-Setup-3.1.0.exe", "browser_download_url": "u2", "size": 9},
                {"name": "SHA256SUMS.txt", "browser_download_url": "u3", "size": 1},
            ])
        )
        assert info.checksum_url == "u3"

    def test_github_digest_field_is_used(self, monkeypatch):
        monkeypatch.setattr("nishizumi_share.updater.sys.platform", "win32")
        digest = "d" * 64
        info = _release_to_update(
            self._release(assets=[
                {"name": "Setup.exe", "browser_download_url": "u", "size": 1, "digest": f"sha256:{digest}"},
            ])
        )
        assert info.expected_sha256 == digest


class TestCheck:
    def _updater(self, monkeypatch, releases, current="3.0.0", prerelease=False):
        updater = Updater(current_version=current, allow_prerelease=prerelease)
        monkeypatch.setattr(Updater, "fetch_releases", lambda self: releases)
        return updater

    def test_returns_none_when_up_to_date(self, monkeypatch, paths):
        updater = self._updater(monkeypatch, [{"tag_name": "v3.0.0", "assets": []}])
        assert updater.check() is None

    def test_finds_newer_release(self, monkeypatch, paths):
        updater = self._updater(monkeypatch, [{"tag_name": "v3.2.0", "assets": []}])
        assert updater.check().version == "3.2.0"

    def test_drafts_are_ignored(self, monkeypatch, paths):
        updater = self._updater(monkeypatch, [{"tag_name": "v9.0.0", "draft": True, "assets": []}])
        assert updater.check() is None

    def test_prereleases_are_ignored_by_default(self, monkeypatch, paths):
        releases = [{"tag_name": "v3.5.0", "prerelease": True, "assets": []}]
        assert self._updater(monkeypatch, releases).check() is None

    def test_prereleases_included_when_opted_in(self, monkeypatch, paths):
        releases = [{"tag_name": "v3.5.0", "prerelease": True, "assets": []}]
        assert self._updater(monkeypatch, releases, prerelease=True).check().version == "3.5.0"

    def test_highest_version_wins(self, monkeypatch, paths):
        releases = [
            {"tag_name": "v3.1.0", "assets": []},
            {"tag_name": "v3.4.0", "assets": []},
            {"tag_name": "v3.2.0", "assets": []},
        ]
        assert self._updater(monkeypatch, releases).check().version == "3.4.0"


class TestDownloadVerification:
    def test_refuses_without_a_checksum(self, monkeypatch, paths):
        from nishizumi_share.updater import UpdateInfo

        updater = Updater(paths=paths)
        info = UpdateInfo(
            version="3.1.0", tag="v3.1.0", notes="", asset_name="Setup.exe",
            asset_url="https://example/Setup.exe", asset_size=10,
        )
        monkeypatch.setattr(Updater, "_fetch_expected_checksum", lambda self, i: "")

        with pytest.raises(UpdateError, match="checksum"):
            updater.download(info)

    def test_rejects_a_release_without_an_installer(self, paths):
        from nishizumi_share.updater import UpdateInfo

        info = UpdateInfo(version="3.1.0", tag="v", notes="", asset_name="", asset_url="", asset_size=0)
        with pytest.raises(UpdateError, match="no installer"):
            Updater(paths=paths).download(info)

    def test_reuses_a_verified_cached_download(self, monkeypatch, paths):
        from nishizumi_share.updater import UpdateInfo

        payload = b"installer-bytes"
        digest = hashlib.sha256(payload).hexdigest()
        cached = paths.update_cache / "Setup.exe"
        cached.write_bytes(payload)

        info = UpdateInfo(
            version="3.1.0", tag="v3.1.0", notes="", asset_name="Setup.exe",
            asset_url="https://example/Setup.exe", asset_size=len(payload),
        )
        monkeypatch.setattr(Updater, "_fetch_expected_checksum", lambda self, i: digest)

        assert Updater(paths=paths).download(info) == cached
