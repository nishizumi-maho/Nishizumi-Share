"""Peer URL handling and local path planning."""

from __future__ import annotations

import pytest

from nishizumi_share.security import NameMapper
from nishizumi_share.syncclient import (
    is_setup_file,
    normalise_peer_url,
    plan_local_path,
)

ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz23456.onion"


class TestNormalisePeerUrl:
    @pytest.mark.parametrize(
        "value",
        [ONION, f"http://{ONION}", f"http://{ONION}/", f"  http://{ONION}/  ", f"HTTP://{ONION.upper()}"],
    )
    def test_accepted_forms_normalise_equally(self, value):
        assert normalise_peer_url(value) == f"http://{ONION}"

    def test_explicit_port_is_kept(self):
        assert normalise_peer_url(f"http://{ONION}:8080") == f"http://{ONION}:8080"

    def test_path_is_discarded(self):
        assert normalise_peer_url(f"http://{ONION}/list") == f"http://{ONION}"

    @pytest.mark.parametrize(
        "value",
        ["", "   ", None, "example.com", "http://example.com", "http://1.2.3.4",
         "ftp://x.onion", "onion", "http://evil.onion.example.com"],
    )
    def test_non_onion_is_rejected(self, value):
        assert normalise_peer_url(value) is None


class TestPlanLocalPath:
    def test_smart_mode_creates_car_folder(self, tmp_path):
        result = plan_local_path(
            "ferrari296gt3/qualy.sto__0123456789abcdef",
            save_dir=str(tmp_path), mode="smart", team_folder="Team",
        )
        assert result == tmp_path / "ferrari296gt3" / "Team" / "qualy.sto"

    def test_smart_mode_nested_directories(self, tmp_path):
        result = plan_local_path(
            "ferrari296gt3/monza/qualy.sto", save_dir=str(tmp_path), mode="smart", team_folder="Team"
        )
        assert result == tmp_path / "ferrari296gt3" / "Team" / "monza" / "qualy.sto"

    def test_smart_mode_bare_file_goes_to_general(self, tmp_path):
        result = plan_local_path("qualy.sto", save_dir=str(tmp_path), mode="smart", team_folder="Team")
        assert result == tmp_path / "_General" / "Team" / "qualy.sto"

    def test_mirror_mode(self, tmp_path):
        result = plan_local_path(
            "ferrari296gt3/qualy.sto", save_dir=str(tmp_path), mode="mirror", team_folder="Team"
        )
        assert result == tmp_path / "Team" / "ferrari296gt3" / "qualy.sto"

    def test_flat_mode_mirrors_source(self, tmp_path):
        result = plan_local_path(
            "ferrari296gt3/qualy.sto", save_dir=str(tmp_path), mode="flat", team_folder="Team"
        )
        assert result == tmp_path / "ferrari296gt3" / "qualy.sto"

    def test_hmac_suffix_is_stripped(self, tmp_path):
        result = plan_local_path(
            "car/setup.sto__0123456789abcdef", save_dir=str(tmp_path), mode="flat"
        )
        assert result.name == "setup.sto"

    @pytest.mark.parametrize(
        "hostile",
        ["../../../etc/passwd", "..\\..\\windows\\system32\\a.dll", "/etc/passwd",
         "a/../../../b.sto", "....//....//x"],
    )
    def test_hostile_names_stay_inside_save_dir(self, tmp_path, hostile):
        result = plan_local_path(hostile, save_dir=str(tmp_path), mode="flat")
        # Either rejected outright, or confined to the destination.
        if result is not None:
            assert tmp_path.resolve() in result.resolve().parents

    def test_empty_name_is_rejected(self, tmp_path):
        assert plan_local_path("", save_dir=str(tmp_path)) is None
        assert plan_local_path("///", save_dir=str(tmp_path)) is None

    def test_missing_save_dir_is_rejected(self):
        assert plan_local_path("a.sto", save_dir="") is None

    def test_team_folder_traversal_is_neutralised(self, tmp_path):
        result = plan_local_path(
            "car/a.sto", save_dir=str(tmp_path), mode="mirror", team_folder="../../evil"
        )
        assert result is not None
        assert tmp_path.resolve() in result.resolve().parents

    def test_round_trip_with_name_mapper(self, tmp_path):
        mapper = NameMapper(b"key")
        public = mapper.public_name("ferrari296gt3/monza qualy.sto")
        result = plan_local_path(public, save_dir=str(tmp_path), mode="smart", team_folder="T")
        assert result == tmp_path / "ferrari296gt3" / "T" / "monza qualy.sto"


class TestIsSetupFile:
    @pytest.mark.parametrize("name", ["a.sto", "A.STO", "x.olap", "y.blap", "z.rpy"])
    def test_setup_extensions(self, name):
        assert is_setup_file(name)

    @pytest.mark.parametrize("name", ["a.txt", "b.exe", "c", "d.sto.txt"])
    def test_other_extensions(self, name):
        assert not is_setup_file(name)
