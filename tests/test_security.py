"""Path safety, sanitisation and name mapping."""

from __future__ import annotations

import os

import pytest

from nishizumi_share.security import (
    NameMapper,
    is_within_directory,
    parse_dlp_rules,
    safe_join,
    sanitize_component,
    strip_hmac_suffix,
    tokens_equal,
)


class TestIsWithinDirectory:
    def test_direct_child(self, tmp_path):
        assert is_within_directory(tmp_path, tmp_path / "a" / "b")

    def test_same_directory(self, tmp_path):
        assert is_within_directory(tmp_path, tmp_path)

    def test_parent_is_rejected(self, tmp_path):
        assert not is_within_directory(tmp_path / "a", tmp_path)

    def test_traversal_is_rejected(self, tmp_path):
        assert not is_within_directory(tmp_path, tmp_path / ".." / "escape")

    def test_sibling_prefix_is_rejected(self, tmp_path):
        # "share2" must not count as inside "share".
        (tmp_path / "share").mkdir()
        (tmp_path / "share2").mkdir()
        assert not is_within_directory(tmp_path / "share", tmp_path / "share2")

    @pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
    def test_symlink_escape_is_rejected(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (base / "link").symlink_to(outside)
        assert not is_within_directory(base, base / "link" / "secret.txt")


class TestSafeJoin:
    def test_simple_join(self, tmp_path):
        assert safe_join(tmp_path, "a", "b.txt") == tmp_path / "a" / "b.txt"

    def test_nested_slashes_are_split(self, tmp_path):
        assert safe_join(tmp_path, "a/b", "c.txt") == tmp_path / "a" / "b" / "c.txt"

    def test_traversal_returns_none(self, tmp_path):
        assert safe_join(tmp_path, "..", "etc") is None
        assert safe_join(tmp_path, "a/../../b") is None

    def test_absolute_component_returns_none(self, tmp_path):
        assert safe_join(tmp_path, "/etc/passwd") is None

    def test_windows_drive_returns_none(self, tmp_path):
        assert safe_join(tmp_path, "C:\\Windows") is None

    def test_empty_returns_none(self, tmp_path):
        assert safe_join(tmp_path) is None
        assert safe_join(tmp_path, "", ".") is None


class TestSanitizeComponent:
    def test_path_separators_removed(self):
        assert "/" not in sanitize_component("a/b")
        assert "\\" not in sanitize_component("a\\b")

    def test_traversal_neutralised(self):
        assert ".." not in sanitize_component("..")

    def test_control_characters_removed(self):
        assert "\x00" not in sanitize_component("a\x00b")

    def test_windows_reserved_names_are_prefixed(self):
        assert sanitize_component("CON") != "CON"
        assert sanitize_component("com1.txt") != "com1.txt"

    def test_extension_survives_truncation(self):
        result = sanitize_component("x" * 500 + ".sto", max_length=50)
        assert result.endswith(".sto")
        assert len(result) <= 50

    def test_never_returns_empty(self):
        assert sanitize_component("") == "_"
        assert sanitize_component("...") == "_"


class TestNameMapper:
    def test_is_deterministic(self):
        mapper = NameMapper(b"key")
        assert mapper.public_name("a/b.sto") == mapper.public_name("a/b.sto")

    def test_differs_per_key(self):
        assert NameMapper(b"k1").public_name("a.sto") != NameMapper(b"k2").public_name("a.sto")

    def test_different_paths_differ(self):
        mapper = NameMapper(b"key")
        assert mapper.public_name("a.sto") != mapper.public_name("b.sto")

    def test_dlp_rules_are_applied(self):
        mapper = NameMapper(b"key", {"secret": "PUBLIC"})
        assert "secret" not in mapper.public_name("secret_car/file.sto").lower()
        assert "PUBLIC" in mapper.public_name("secret_car/file.sto")

    def test_dlp_replaces_every_occurrence(self):
        mapper = NameMapper(b"key", {"x": "Y"})
        assert "x" not in mapper.public_name("xxx.sto").split("__")[0]

    def test_dlp_is_case_insensitive(self):
        mapper = NameMapper(b"key", {"secret": "PUB"})
        assert "PUB" in mapper.public_name("SeCrEt.sto")

    def test_round_trip_through_strip(self):
        mapper = NameMapper(b"key")
        assert strip_hmac_suffix(mapper.public_name("car/file.sto")) == "car/file.sto"

    def test_directory_structure_preserved(self):
        mapper = NameMapper(b"key")
        assert mapper.public_name("a/b/c.sto").count("/") == 2


class TestStripHmacSuffix:
    def test_removes_suffix(self):
        assert strip_hmac_suffix("car/file.sto__0123456789abcdef") == "car/file.sto"

    def test_leaves_plain_names(self):
        assert strip_hmac_suffix("car/file.sto") == "car/file.sto"

    def test_ignores_wrong_length(self):
        assert strip_hmac_suffix("file__0123") == "file__0123"

    def test_ignores_non_hex(self):
        assert strip_hmac_suffix("file__zzzzzzzzzzzzzzzz") == "file__zzzzzzzzzzzzzzzz"

    def test_preserves_double_underscores_in_name(self):
        # Only the trailing 16-hex block is a suffix; the 2.x rsplit("__")
        # implementation mangled names like this one.
        assert strip_hmac_suffix("my__file.sto") == "my__file.sto"

    def test_only_last_component_affected(self):
        assert strip_hmac_suffix("a__0123456789abcdef/b.sto") == "a__0123456789abcdef/b.sto"

    def test_never_empties_basename(self):
        assert strip_hmac_suffix("__0123456789abcdef") == "__0123456789abcdef"


class TestDlpRules:
    def test_parsing(self):
        rules = parse_dlp_rules("a=B\n# comment\n\nc = D \nbad-line")
        assert rules == {"a": "B", "c": "D"}

    def test_empty_value_allowed(self):
        assert parse_dlp_rules("secret=") == {"secret": ""}


class TestTokens:
    def test_equal(self):
        assert tokens_equal("abc", "abc")

    def test_not_equal(self):
        assert not tokens_equal("abc", "abd")

    def test_empty_never_matches(self):
        assert not tokens_equal("", "")
        assert not tokens_equal("", "x")

    def test_unicode_is_safe(self):
        assert tokens_equal("tökén", "tökén")
        assert not tokens_equal("tökén", "token")
