"""Flask routes, snapshot lifecycle and access control."""

from __future__ import annotations

import time
from urllib.parse import quote

import pytest

from nishizumi_share.avscan import AntivirusScanner, ScanResult
from nishizumi_share.server import ShareState, create_app


@pytest.fixture()
def state(settings, share_dir):
    settings.update({"upload_limit_bps": 0, "share_dir": str(share_dir)})
    share_state = ShareState(settings)
    share_state.share_dir = str(share_dir)
    return share_state


@pytest.fixture()
def client(state):
    app = create_app(state)
    app.config.update(TESTING=True)
    return app.test_client()


def get_listing(client, token: str = ""):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get("/list", headers=headers)


def download(client, map_id: str, name: str, token: str):
    return client.get(
        f"/download/{map_id}/{quote(name, safe='/')}",
        headers={"Authorization": f"Bearer {token}"},
    )


class TestListing:
    def test_health(self, client):
        assert client.get("/health").get_json()["status"] == "ok"

    def test_lists_all_files(self, client):
        payload = get_listing(client).get_json()
        assert len(payload["files"]) == 3
        assert payload["map_id"] and payload["map_token"]

    def test_real_paths_are_never_exposed(self, client, share_dir):
        body = get_listing(client).get_data(as_text=True)
        assert str(share_dir) not in body

    def test_names_carry_hmac_suffix(self, client):
        for entry in get_listing(client).get_json()["files"]:
            assert "__" in entry["path"]

    def test_sizes_are_reported(self, client):
        assert all(entry["size"] >= 0 for entry in get_listing(client).get_json()["files"])

    def test_not_ready_without_share_dir(self, state, client):
        state.share_dir = ""
        assert get_listing(client).status_code == 503

    def test_hidden_files_are_skipped(self, client, share_dir):
        (share_dir / ".quarantine").mkdir()
        (share_dir / ".quarantine" / "partial.tmp").write_bytes(b"x")
        names = [f["path"] for f in get_listing(client).get_json()["files"]]
        assert not any("quarantine" in n for n in names)


class TestListAccessToken:
    def test_token_required_when_configured(self, state, client, settings):
        settings.update({"require_list_token": True, "list_access_token": "sesame"})
        assert get_listing(client).status_code == 401
        assert get_listing(client, "sesame").status_code == 200

    def test_wrong_token_rejected(self, state, client, settings):
        settings.update({"require_list_token": True, "list_access_token": "sesame"})
        assert get_listing(client, "nope").status_code == 401

    def test_fails_closed_when_token_missing(self, state, client, settings):
        settings.update({"require_list_token": True, "list_access_token": ""})
        assert get_listing(client, "anything").status_code == 401


class TestDownload:
    def test_happy_path(self, client):
        payload = get_listing(client).get_json()
        entry = payload["files"][0]
        response = download(client, payload["map_id"], entry["path"], payload["map_token"])
        assert response.status_code == 200
        assert len(response.get_data()) == entry["size"]

    def test_content_length_is_set(self, client):
        payload = get_listing(client).get_json()
        entry = payload["files"][0]
        response = download(client, payload["map_id"], entry["path"], payload["map_token"])
        assert int(response.headers["Content-Length"]) == entry["size"]

    def test_missing_token_is_rejected(self, client):
        payload = get_listing(client).get_json()
        name = payload["files"][0]["path"]
        assert client.get(f"/download/{payload['map_id']}/{quote(name)}").status_code == 401

    def test_wrong_token_is_rejected(self, client):
        payload = get_listing(client).get_json()
        response = download(client, payload["map_id"], payload["files"][0]["path"], "wrong")
        assert response.status_code == 401

    def test_token_from_another_snapshot_is_rejected(self, client):
        first = get_listing(client).get_json()
        second = get_listing(client).get_json()
        response = download(client, second["map_id"], second["files"][0]["path"], first["map_token"])
        assert response.status_code == 401

    def test_unknown_snapshot_is_rejected(self, client):
        payload = get_listing(client).get_json()
        response = download(client, "deadbeef", payload["files"][0]["path"], payload["map_token"])
        assert response.status_code == 401

    def test_unlisted_name_is_rejected(self, client):
        payload = get_listing(client).get_json()
        response = download(client, payload["map_id"], "anything.sto", payload["map_token"])
        assert response.status_code == 404

    @pytest.mark.parametrize(
        "attack", ["../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd"]
    )
    def test_traversal_is_rejected(self, client, attack):
        payload = get_listing(client).get_json()
        response = client.get(
            f"/download/{payload['map_id']}/{attack}",
            headers={"Authorization": f"Bearer {payload['map_token']}"},
        )
        assert response.status_code in (404, 400, 403)

    def test_stats_are_recorded(self, state, client):
        payload = get_listing(client).get_json()
        download(client, payload["map_id"], payload["files"][0]["path"], payload["map_token"])
        assert state.stats.files_served == 1
        assert state.stats.bytes_served > 0

    def test_callback_fires(self, state, client):
        seen = []
        state.on_file_served = lambda name, size: seen.append((name, size))
        payload = get_listing(client).get_json()
        download(client, payload["map_id"], payload["files"][0]["path"], payload["map_token"])
        assert len(seen) == 1

    def test_deleted_file_returns_404(self, client, share_dir):
        payload = get_listing(client).get_json()
        entry = next(e for e in payload["files"] if e["path"].startswith("readme"))
        (share_dir / "readme.md").unlink()
        response = download(client, payload["map_id"], entry["path"], payload["map_token"])
        assert response.status_code == 404


class TestSnapshotLifecycle:
    def test_expiry(self, settings, share_dir):
        state = ShareState(settings, snapshot_ttl=0)
        state.share_dir = str(share_dir)
        snapshot = state.build_snapshot()
        time.sleep(0.01)
        assert state.get_snapshot(snapshot.snapshot_id) is None

    def test_live_snapshot_is_retained(self, state):
        snapshot = state.build_snapshot()
        assert state.get_snapshot(snapshot.snapshot_id) is not None

    def test_snapshots_are_capped(self, state, monkeypatch):
        monkeypatch.setattr("nishizumi_share.server.MAX_SNAPSHOTS", 3)
        ids = [state.build_snapshot().snapshot_id for _ in range(6)]
        alive = [i for i in ids if state.get_snapshot(i) is not None]
        assert len(alive) <= 4

    def test_changing_share_dir_invalidates_snapshots(self, state, tmp_path):
        snapshot = state.build_snapshot()
        state.share_dir = str(tmp_path)
        assert state.get_snapshot(snapshot.snapshot_id) is None


class TestOneTimeTokens:
    def test_grants_access_to_its_snapshot(self, state, client):
        token = state.issue_one_time_token(600)
        snapshot = state.get_snapshot(token.snapshot_id)
        name = snapshot.files[0]["path"]
        assert download(client, token.snapshot_id, name, token.token).status_code == 200

    def test_rejected_for_other_snapshots(self, state, client):
        token = state.issue_one_time_token(600)
        other = get_listing(client).get_json()
        response = download(client, other["map_id"], other["files"][0]["path"], token.token)
        assert response.status_code == 401

    def test_expired_token_is_rejected(self, state, client):
        token = state.issue_one_time_token(600)
        token.expires_at = time.time() - 1
        snapshot = state.get_snapshot(token.snapshot_id)
        assert download(client, token.snapshot_id, snapshot.files[0]["path"], token.token).status_code == 401


class TestAntivirusGate:
    def test_blocked_file_is_not_served(self, state, client, monkeypatch):
        state.settings.update({"av_enabled": True})
        monkeypatch.setattr(
            AntivirusScanner, "scan",
            lambda self, path, **kw: ScanResult(False, "infected", "eicar"),
        )
        payload = get_listing(client).get_json()
        response = download(client, payload["map_id"], payload["files"][0]["path"], payload["map_token"])
        assert response.status_code == 403
        assert response.get_json()["error"] == "blocked_by_av"

    def test_disabled_scanner_allows_everything(self, state, client):
        state.settings.update({"av_enabled": False})
        payload = get_listing(client).get_json()
        response = download(client, payload["map_id"], payload["files"][0]["path"], payload["map_token"])
        assert response.status_code == 200


class TestRateLimiting:
    def test_excess_requests_are_rejected(self, state, monkeypatch):
        monkeypatch.setattr("nishizumi_share.server.SlidingWindowRateLimiter.allow", lambda self: False)
        app = create_app(state)
        app.config.update(TESTING=True)
        assert app.test_client().get("/list").status_code == 429
