# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [3.0.0] - 2026-08-18

A full rewrite. The three half-finished scripts (`main full.py`,
`client lite.py`, `server lite.py`) are replaced by one application shipped as
a single Windows installer that updates itself.

### Added
- **Single setup installer** — `NishizumiShare-Setup-3.0.0.exe`, built by
  PyInstaller + Inno Setup. Installs per-user, so updates need no UAC prompt.
- **Automatic updates** — the app checks GitHub Releases, downloads the new
  installer, verifies its SHA-256 against the release checksum file, and
  installs silently. An update whose checksum cannot be confirmed is refused.
  Update checks can be routed through Tor.
- **Real Tor bootstrap detection** — progress is read from the control port
  (`GETINFO status/bootstrap-phase`) instead of being assumed. The UI now shows
  actual bootstrap percentage and reports genuine failures.
- **Bundled Tor is fetched and verified at build time** against the checksums
  published by the Tor Project; it is never committed to the repository.
- **Access control for listings** — an optional shared token can be required
  before a peer may list your files.
- **Settings migration** from 2.x configuration directories, including the
  onion key, peer list and DLP rules.
- **230 automated tests** plus CI on Windows and Linux.
- Configurable sync interval, ports, bandwidth caps and file-size limit.
- Log file with rotation, viewable in the app and on disk.

### Fixed
- **Antivirus blocked every transfer when no scanner was installed.** "No
  scanner found" was treated as "infected". Scanning is now genuinely optional,
  defaults to allowing files when no scanner exists, and offers an explicit
  fail-closed setting for those who want it.
- **The antivirus setting did nothing.** A global `AV_DISABLE_GLOBAL = True`
  constant silently overrode the user's choice in the 2.x main app.
- **Stopping the server killed the whole application** — the lite server called
  `os._exit(0)`. The HTTP server can now be started and stopped repeatedly, and
  the main app had no way to stop the server at all before.
- **Onion identity changed on every restart.** The control-port parser split
  private keys on `=`, truncating the base64 padding, so the stored key was
  never valid on restore.
- **Download progress never moved** on the main app: responses carried no
  `Content-Length`. It is now always set, and a truncated transfer is detected
  and retried instead of being silently saved.
- **Peers with a trailing slash were silently ignored** — the check was
  `peer.endswith(".onion")`. Addresses are now parsed properly, and anything
  that is not an onion is rejected so traffic cannot leak to the clearnet.
- **Filenames containing `__` were mangled** by the client's `rsplit("__")`
  suffix stripping. Only a trailing 16-hex-character block is removed now.
- **Only `.sto` files were ever synced** — the filter was hardcoded to `True`
  in the main app with no way to change it. It is now a setting, off by default.
- **The "files served" counter never moved**; the signal that fed it was never
  emitted.
- Shared state (snapshots, tokens, rate-limit counters) is now locked; it was
  read and written from several server threads without synchronisation.
- Repeated `/list` calls could grow memory without bound; snapshots are now
  capped and expired.
- Partial downloads are cleaned up on start-up instead of accumulating in
  `.quarantine` forever.
- Settings are validated and written atomically; a corrupt or hand-edited file
  no longer prevents start-up.
- A token bucket asked for more bytes than its capacity looped forever; the
  request is now clamped.
- Absolute paths passed to the path joiner are rejected rather than silently
  reinterpreted as relative.
- Tor is terminated reliably on exit, and only processes this app started are
  ever killed.

### Changed
- Layout modes are now named `smart`, `mirror` and `flat` instead of the
  magic numbers 3 and 2.
- Configuration lives in a platform-appropriate directory
  (`%APPDATA%\NishizumiShare`, `~/Library/Application Support/NishizumiShare`,
  `$XDG_CONFIG_HOME/nishizumi-share`).
- The GUI is reorganised into Sync / Share / Settings / Logs, and long
  operations no longer freeze the window.
- Long-running work reports progress; Tor bootstrap can take a minute and the
  UI now says so rather than appearing hung.

### Removed
- `main full.py`, `client lite.py` and `server lite.py`, superseded by the
  `nishizumi_share` package.
- The dead `AV_DISABLE_GLOBAL` kill switch and the unused `map_sig` field.

## [2.2.1] - 2025
- Client stripped HMAC suffixes from saved filenames.
- Antivirus scanning disabled by default.
- Lite client gained smarter Tor detection.

## [2.1.0] - 2025
- First public release: DLP rules and ephemeral tokens.
