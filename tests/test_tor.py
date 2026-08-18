"""Tor control-protocol parsing and binary discovery."""

from __future__ import annotations

import os
import sys

import pytest

from nishizumi_share.tor import (
    TorController,
    _ensure_executable,
    find_free_port,
    parse_key_value,
    resolve_tor_binary,
    socks_proxies,
)


class TestParseKeyValue:
    def test_simple_pair(self):
        assert parse_key_value("250-ServiceID=abc123") == ("ServiceID", "abc123")

    def test_status_prefix_variants(self):
        assert parse_key_value("250 ServiceID=abc") == ("ServiceID", "abc")
        assert parse_key_value("250+ServiceID=abc") == ("ServiceID", "abc")

    def test_base64_padding_survives(self):
        # The 2.x parser used split("=")[1] and truncated keys at the padding,
        # which produced an unusable private key and a new onion every restart.
        line = "250-PrivateKey=ED25519-V3:aGVsbG8gd29ybGQgdGhpcyBpcyBhIGtleQ=="
        key, value = parse_key_value(line)
        assert key == "PrivateKey"
        assert value == "ED25519-V3:aGVsbG8gd29ybGQgdGhpcyBpcyBhIGtleQ=="

    def test_value_containing_equals(self):
        assert parse_key_value("250-A=b=c")[1] == "b=c"

    def test_line_without_equals(self):
        assert parse_key_value("250 OK") is None


class TestParseAddOnion:
    def test_extracts_both_fields(self):
        lines = [
            "250-ServiceID=xyz7abc",
            "250-PrivateKey=ED25519-V3:c2VjcmV0a2V5ZGF0YQ==",
            "250 OK",
        ]
        service_id, private_key = TorController._parse_add_onion(lines)
        assert service_id == "xyz7abc"
        assert private_key == "ED25519-V3:c2VjcmV0a2V5ZGF0YQ=="

    def test_missing_fields_return_none(self):
        assert TorController._parse_add_onion(["550 Bad key"]) == (None, None)


class TestParseBootstrap:
    def test_progress_and_summary(self):
        line = '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=75 TAG=loading SUMMARY="Loading"'
        assert TorController._parse_bootstrap([line]) == (75, "Loading")

    def test_complete(self):
        line = '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"'
        percent, _summary = TorController._parse_bootstrap([line])
        assert percent == 100

    def test_unrelated_lines(self):
        assert TorController._parse_bootstrap(["250 OK"]) == (None, "")


class TestPorts:
    def test_find_free_port_returns_bindable_port(self):
        port = find_free_port(0)
        assert 1 <= port <= 65535

    def test_socks_proxies_use_socks5h(self):
        # socks5h keeps DNS inside Tor, which .onion resolution requires.
        proxies = socks_proxies(9050)
        assert proxies["http"].startswith("socks5h://")
        assert proxies["https"].startswith("socks5h://")


class TestResolveTorBinary:
    def test_external_path_is_used_when_present(self, tmp_path, monkeypatch):
        fake = tmp_path / "tor"
        fake.write_text("#!/bin/sh\n")
        monkeypatch.setattr("nishizumi_share.tor.find_bundled_tor", lambda: None)
        monkeypatch.setattr("nishizumi_share.tor.find_system_tor", lambda: None)
        assert resolve_tor_binary("external", str(fake)) == str(fake)

    def test_embedded_prefers_the_bundle(self, monkeypatch):
        monkeypatch.setattr("nishizumi_share.tor.find_bundled_tor", lambda: "/bundled/tor")
        monkeypatch.setattr("nishizumi_share.tor.find_system_tor", lambda: "/usr/bin/tor")
        assert resolve_tor_binary("embedded", "") == "/bundled/tor"

    def test_embedded_falls_back_to_system(self, monkeypatch):
        monkeypatch.setattr("nishizumi_share.tor.find_bundled_tor", lambda: None)
        monkeypatch.setattr("nishizumi_share.tor.find_system_tor", lambda: "/usr/bin/tor")
        assert resolve_tor_binary("embedded", "") == "/usr/bin/tor"

    def test_nothing_found(self, monkeypatch):
        monkeypatch.setattr("nishizumi_share.tor.find_bundled_tor", lambda: None)
        monkeypatch.setattr("nishizumi_share.tor.find_system_tor", lambda: None)
        assert resolve_tor_binary("embedded", "") is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
class TestEnsureExecutable:
    def test_adds_missing_bit(self, tmp_path):
        target = tmp_path / "tor"
        target.write_text("#!/bin/sh\n")
        target.chmod(0o644)
        assert _ensure_executable(target)
        assert os.access(target, os.X_OK)

    def test_already_executable(self, tmp_path):
        target = tmp_path / "tor"
        target.write_text("#!/bin/sh\n")
        target.chmod(0o755)
        assert _ensure_executable(target)
