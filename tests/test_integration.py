"""End-to-end: a real HTTP server serving a real sync client over loopback.

Tor is not involved — the SOCKS proxy is stripped from the client session so
the same code path runs against 127.0.0.1.
"""

from __future__ import annotations

import threading
import time

import pytest

from nishizumi_share.config import Settings
from nishizumi_share.server import HttpServer, ShareState, create_app
from nishizumi_share.syncclient import PeerClient, SyncEngine
from nishizumi_share.throttle import TokenBucket
from nishizumi_share.tor import find_free_port


@pytest.fixture()
def live_server(settings, share_dir):
    """A running share server; yields its base URL."""
    settings.update({"upload_limit_bps": 0, "share_dir": str(share_dir)})
    state = ShareState(settings)
    state.share_dir = str(share_dir)

    port = find_free_port(0)
    server = HttpServer(create_app(state), host="127.0.0.1", port=port)
    server.start()

    # Wait for the listener to accept connections.
    deadline = time.monotonic() + 10
    import socket

    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.05)
    else:  # pragma: no cover
        server.stop()
        pytest.fail("server did not start")

    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        server.stop()


@pytest.fixture()
def direct_client():
    """A PeerClient with the Tor proxy removed so it can reach loopback."""
    client = PeerClient(socks_port=9050)
    client._session.proxies.clear()
    try:
        yield client
    finally:
        client.close()


class TestPeerClient:
    def test_fetch_listing(self, live_server, direct_client):
        url, _state = live_server
        listing = direct_client.fetch_listing(url)
        assert len(listing.files) == 3
        assert listing.map_id and listing.map_token

    def test_download_matches_source(self, live_server, direct_client, tmp_path, share_dir):
        url, _state = live_server
        listing = direct_client.fetch_listing(url)
        remote = next(f for f in listing.files if "monza" in f.public_name)

        destination = tmp_path / "out.sto"
        written = direct_client.download(
            url, listing, remote, destination,
            bucket=TokenBucket.from_rate(0), stop_event=threading.Event(),
        )

        original = (share_dir / "ferrari296gt3" / "monza_qualy.sto").read_bytes()
        assert written == len(original)
        assert destination.read_bytes() == original

    def test_expired_snapshot_reports_clearly(self, live_server, direct_client, tmp_path):
        url, state = live_server
        listing = direct_client.fetch_listing(url)
        remote = listing.files[0]
        state.share_dir = str(tmp_path)  # invalidates snapshots

        from nishizumi_share.syncclient import PeerError

        with pytest.raises(PeerError):
            direct_client.download(
                url, listing, remote, tmp_path / "x",
                bucket=TokenBucket.from_rate(0), stop_event=threading.Event(),
            )

    def test_bad_token_is_reported(self, live_server, direct_client, tmp_path):
        url, _state = live_server
        listing = direct_client.fetch_listing(url)
        listing.map_token = "wrong"

        from nishizumi_share.syncclient import PeerError

        with pytest.raises(PeerError):
            direct_client.download(
                url, listing, listing.files[0], tmp_path / "x",
                bucket=TokenBucket.from_rate(0), stop_event=threading.Event(),
            )


class TestSyncEngine:
    @pytest.fixture()
    def engine(self, live_server, settings, tmp_path, monkeypatch):
        url, _state = live_server
        save_dir = tmp_path / "downloads"
        save_dir.mkdir()

        settings.update({
            "save_dir": str(save_dir),
            "peers": [url],
            "sync_mode": "smart",
            "team_folder": "Team",
            "download_limit_bps": 0,
            "only_setup_files": False,
        })

        # Accept the loopback peer and skip the Tor proxy.
        monkeypatch.setattr("nishizumi_share.syncclient.normalise_peer_url", lambda p: p)

        real_init = PeerClient.__init__

        def patched_init(self, socks_port, access_token=""):
            real_init(self, socks_port, access_token)
            self._session.proxies.clear()

        monkeypatch.setattr(PeerClient, "__init__", patched_init)

        return SyncEngine(settings, socks_port=9050), save_dir

    def test_downloads_everything_once(self, engine):
        sync, save_dir = engine
        stats = sync.run_once()

        assert stats.downloaded == 3
        assert stats.failed == 0
        assert (save_dir / "ferrari296gt3" / "Team" / "monza_qualy.sto").exists()
        assert (save_dir / "_General" / "Team" / "readme.md").exists()

    def test_second_pass_skips_existing(self, engine):
        sync, _save_dir = engine
        sync.run_once()
        stats = sync.run_once()

        assert stats.downloaded == 0
        assert stats.skipped == 3

    def test_changed_file_is_re_downloaded(self, engine, share_dir):
        sync, save_dir = engine
        sync.run_once()

        (share_dir / "readme.md").write_bytes(b"much longer content than before")
        stats = sync.run_once()

        assert stats.downloaded == 1
        assert (save_dir / "_General" / "Team" / "readme.md").read_bytes().startswith(b"much longer")

    def test_only_setup_files_filter(self, engine, settings):
        sync, save_dir = engine
        settings.update({"only_setup_files": True})
        stats = sync.run_once()

        assert stats.downloaded == 1
        assert (save_dir / "ferrari296gt3" / "Team" / "monza_qualy.sto").exists()
        assert not (save_dir / "_General" / "Team" / "readme.md").exists()

    def test_mirror_layout(self, engine, settings):
        sync, save_dir = engine
        settings.update({"sync_mode": "mirror"})
        sync.run_once()
        assert (save_dir / "Team" / "ferrari296gt3" / "monza_qualy.sto").exists()

    def test_size_limit_is_enforced(self, engine, settings):
        sync, save_dir = engine
        # Only the 1000-byte setup exceeds this; the two small files still sync.
        settings.update({"max_file_size": 100})
        stats = sync.run_once()

        assert stats.skipped == 1
        assert stats.downloaded == 2
        assert not (save_dir / "ferrari296gt3" / "Team" / "monza_qualy.sto").exists()
        assert (save_dir / "_General" / "Team" / "readme.md").exists()

    def test_no_partial_files_are_left_behind(self, engine):
        sync, save_dir = engine
        sync.run_once()
        quarantine = save_dir / ".quarantine"
        assert not list(quarantine.iterdir())

    def test_stop_event_halts_the_pass(self, engine):
        sync, _save_dir = engine
        sync.stop()
        stats = sync.run_once()
        assert stats.downloaded == 0

    def test_unreachable_peer_is_reported_not_raised(self, settings, tmp_path, monkeypatch):
        save_dir = tmp_path / "d"
        save_dir.mkdir()
        settings.update({"save_dir": str(save_dir), "peers": ["http://127.0.0.1:1/"]})
        monkeypatch.setattr("nishizumi_share.syncclient.normalise_peer_url", lambda p: p)

        messages = []
        sync = SyncEngine(settings, socks_port=9050, on_log=messages.append)
        stats = sync.run_once()

        assert stats.failed == 1
        assert any("127.0.0.1" in m or "unreachable" in m for m in messages)

    def test_missing_destination_is_handled(self, settings):
        settings.update({"save_dir": "", "peers": ["x.onion"]})
        stats = SyncEngine(settings, socks_port=9050).run_once()
        assert stats.downloaded == 0


class TestQuarantineCleanup:
    def test_stale_partials_are_removed(self, tmp_path):
        import os

        save_dir = tmp_path / "d"
        quarantine = save_dir / ".quarantine"
        quarantine.mkdir(parents=True)

        stale = quarantine / "old.part"
        stale.write_bytes(b"x")
        old = time.time() - 48 * 3600
        os.utime(stale, (old, old))

        fresh = quarantine / "new.part"
        fresh.write_bytes(b"x")

        assert SyncEngine.cleanup_quarantine(str(save_dir)) == 1
        assert not stale.exists()
        assert fresh.exists()
