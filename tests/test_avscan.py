"""Antivirus gating semantics."""

from __future__ import annotations

import pytest

from nishizumi_share.avscan import AntivirusScanner, ScanResult


@pytest.fixture()
def sample(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"payload")
    return target


class TestScanPolicy:
    def test_disabled_allows_without_scanning(self, paths, sample, monkeypatch):
        monkeypatch.setattr(
            "nishizumi_share.avscan.scan_with_clamav",
            lambda path: pytest.fail("scanner must not run when disabled"),
        )
        result = AntivirusScanner(paths).scan(sample, enabled=False)
        assert result.allowed and result.status == "disabled"

    def test_missing_scanner_allows_by_default(self, paths, sample, monkeypatch):
        # This is the 2.x regression: "no scanner" used to mean "blocked",
        # which stopped every transfer on machines without an AV installed.
        monkeypatch.setattr("nishizumi_share.avscan.defender_path", lambda: None)
        monkeypatch.setattr("nishizumi_share.avscan.clamav_path", lambda: None)
        result = AntivirusScanner(paths).scan(sample, enabled=True)
        assert result.allowed
        assert result.status == "unavailable"

    def test_missing_scanner_blocks_when_fail_closed(self, paths, sample, monkeypatch):
        monkeypatch.setattr("nishizumi_share.avscan.defender_path", lambda: None)
        monkeypatch.setattr("nishizumi_share.avscan.clamav_path", lambda: None)
        result = AntivirusScanner(paths).scan(sample, enabled=True, block_when_unavailable=True)
        assert result.blocked

    def test_infected_is_blocked(self, paths, sample, monkeypatch):
        monkeypatch.setattr(
            "nishizumi_share.avscan.scan_with_clamav",
            lambda path: ScanResult(False, "infected", "Eicar-Test-Signature"),
        )
        monkeypatch.setattr("nishizumi_share.avscan.sys.platform", "linux")
        assert AntivirusScanner(paths).scan(sample, enabled=True).blocked

    def test_clean_is_allowed(self, paths, sample, monkeypatch):
        monkeypatch.setattr("nishizumi_share.avscan.sys.platform", "linux")
        monkeypatch.setattr(
            "nishizumi_share.avscan.scan_with_clamav", lambda path: ScanResult(True, "clean")
        )
        assert AntivirusScanner(paths).scan(sample, enabled=True).allowed

    def test_missing_file_is_blocked(self, paths, tmp_path):
        result = AntivirusScanner(paths).scan(tmp_path / "nope.bin", enabled=True)
        assert result.blocked and result.status == "error"


class TestCache:
    def test_verdicts_are_cached(self, paths, sample, monkeypatch):
        calls = []
        monkeypatch.setattr("nishizumi_share.avscan.sys.platform", "linux")

        def fake_scan(path):
            calls.append(path)
            return ScanResult(True, "clean")

        monkeypatch.setattr("nishizumi_share.avscan.scan_with_clamav", fake_scan)

        scanner = AntivirusScanner(paths)
        scanner.scan(sample, enabled=True)
        scanner.scan(sample, enabled=True)
        assert len(calls) == 1

    def test_transient_errors_are_not_cached(self, paths, sample, monkeypatch):
        calls = []
        monkeypatch.setattr("nishizumi_share.avscan.sys.platform", "linux")

        def fake_scan(path):
            calls.append(path)
            return ScanResult(True, "error", "timeout")

        monkeypatch.setattr("nishizumi_share.avscan.scan_with_clamav", fake_scan)

        scanner = AntivirusScanner(paths)
        scanner.scan(sample, enabled=True)
        scanner.scan(sample, enabled=True)
        assert len(calls) == 2
