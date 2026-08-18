# Nishizumi Share

<img width="512" alt="Nishizumi Share" src="https://github.com/user-attachments/assets/4951276a-0260-4565-b107-9673046bf23e" />

**Anonymous file sharing over Tor hidden services.**

Nishizumi Share keeps a folder in sync between people who trust each other,
without a server in the middle and without either side learning the other's IP
address. Each person publishes a `.onion` address; everyone else points the app
at it and their files arrive automatically.

It was built for sim-racing teams passing car setups around, but nothing in it
is specific to that.

[![CI](https://github.com/nishizumi-maho/Nishizumi-Share/actions/workflows/ci.yml/badge.svg)](https://github.com/nishizumi-maho/Nishizumi-Share/actions/workflows/ci.yml)

---

## Install

Download the latest **`NishizumiShare-Setup-<version>.exe`** from the
[Releases page](https://github.com/nishizumi-maho/Nishizumi-Share/releases/latest)
and run it.

That single installer contains everything, including Tor — there is nothing
else to download or configure. It installs for the current user only, so it
never asks for administrator rights.

**The app keeps itself up to date.** It checks GitHub for new releases, verifies
the download's SHA-256 against the checksum published with the release, and
installs it silently. An update that fails verification is discarded. You can
turn this off in *Settings → Updates*.

<details>
<summary>Verifying the installer by hand</summary>

```powershell
Get-FileHash -Algorithm SHA256 NishizumiShare-Setup-3.0.0.exe
```

Compare the result with `SHA256SUMS.txt`, attached to the same release.
</details>

### Linux and macOS

There is no packaged build yet, but the app runs from source:

```bash
git clone https://github.com/nishizumi-maho/Nishizumi-Share.git
cd Nishizumi-Share
python -m pip install -r requirements.txt
python -m nishizumi_share
```

You will need Tor installed (`apt install tor`, `brew install tor`) or the
[Tor Expert Bundle](https://www.torproject.org/download/tor/) unpacked into a
`tor/` folder next to the project. Automatic updates are Windows-only; on other
platforms the app tells you a new version exists and links to it.

---

## Using it

The window has four tabs. You only need the first two.

### Sync — receive files

1. Pick the folder downloads should land in (for iRacing, your `setups` folder).
2. Paste your teammates' `.onion` addresses, one per line.
3. Choose how downloads should be laid out (see below).
4. Press **START SYNC**.

Tor starts automatically. The first connection takes 30–60 seconds while Tor
bootstraps; after that the app polls each peer every 30 seconds and downloads
anything new or changed.

**Layouts**

| Mode | Result |
|---|---|
| **Smart** | `setups/ferrari296gt3/Team_Setups/monza.sto` — a folder per car. This is what iRacing expects. |
| **Mirror** | `setups/Team_Setups/ferrari296gt3/monza.sto` — the peer's tree inside one team folder. |
| **Exact** | `setups/ferrari296gt3/monza.sto` — reproduces the peer's tree as-is. |

### Share — send files

1. Pick the folder you want to share.
2. Press **START SHARING**.
3. Copy the `.onion` address that appears and send it to your team.

Your address is stable: it is stored and reused every time you share, so you
only distribute it once. *Settings → Reset .onion identity* generates a new one
if it is ever exposed.

Two optional controls live on this tab:

- **Access token** — require a shared secret before anyone can even list your
  files. Without it, anyone who learns your `.onion` can see the listing.
- **One-time token** — a link that works for a set number of minutes, for
  sharing with someone outside the team.

### Settings and Logs

Tor source and ports, bandwidth caps, maximum file size, sync interval,
antivirus, updates, and start-with-system. The Logs tab shows what the app is
doing and is the first place to look when something misbehaves.

---

## How it works

```
  Your machine                    Tor network                  Teammate
 ┌──────────────┐                                          ┌──────────────┐
 │ shared/      │                                          │ setups/      │
 │   └ car/     │                                          │   └ car/     │
 │      a.sto   │                                          │      a.sto   │
 ├──────────────┤   .onion (v3 hidden service)             ├──────────────┤
 │ HTTP server  │ ◄──────────────────────────────────────  │ sync client  │
 │ 127.0.0.1    │        SOCKS5h, never leaves Tor         │              │
 └──────────────┘                                          └──────────────┘
```

1. **Publishing.** The app starts Tor, publishes a v3 hidden service, and runs a
   small HTTP server bound to localhost. Only Tor can reach it.
2. **Listing.** A peer asks for `/list` and gets a *snapshot*: the files
   available right now, plus a bearer token. Snapshots expire after 10 minutes.
3. **Names.** Real paths are never sent. Each file is advertised under a
   sanitised name with a short keyed HMAC suffix, which the server uses to look
   the file back up. Clients strip the suffix when saving, so files land with
   readable names.
4. **Downloading.** The client quotes the snapshot id and token, streams the
   file into a `.quarantine` folder, checks its size, optionally scans it, and
   only then moves it into place. Interrupted transfers never leave a partial
   file where a real one should be.

### What this protects against, and what it does not

**It does protect** your IP address from your peers and from anyone watching the
network, and it hides your real folder structure and filenames from peers.

**It does not** encrypt files at rest, verify *who* is on the other end beyond
possession of your `.onion` address (and access token, if you set one), or
protect you from a teammate who chooses to leak what you sent them. Treat your
`.onion` address as a credential: anyone who has it can list your shared folder.

---

## Configuration

Settings live in:

| Platform | Location |
|---|---|
| Windows | `%APPDATA%\NishizumiShare\` |
| macOS | `~/Library/Application Support/NishizumiShare/` |
| Linux | `$XDG_CONFIG_HOME/nishizumi-share/` (usually `~/.config/`) |

| File | Purpose |
|---|---|
| `settings.json` | All preferences |
| `onion_private_key` | Your `.onion` identity — **back this up** |
| `security_rules.txt` | Filename privacy rules |
| `logs/nishizumi.log` | Rotating log |

Settings from 2.x installations are imported automatically on first run,
including the onion key, so your address does not change when you upgrade.

### Filename privacy rules

Names your peers see can be rewritten before they leave your machine. On the
Share tab, one rule per line:

```
internal=PUBLIC
MyRealTeamName=TEAM
```

A file named `MyRealTeamName_internal_notes.sto` is then advertised as
`TEAM_PUBLIC_notes.sto`.

### Antivirus (off by default)

When enabled, files are scanned with Microsoft Defender on Windows or ClamAV
elsewhere before being served or saved. If no scanner is installed, files are
allowed through and the reason is logged; tick *Block transfers when no
antivirus is available* if you would rather fail closed.

---

## Troubleshooting

**Tor will not start.** Check the Logs tab. The usual causes are a missing
`tor/` folder next to the app, or a firewall blocking Tor. *Settings → Tor*
shows which binary was detected.

**Bootstrap times out.** Tor is blocked on your network or by your ISP. Try a
different connection; bridges are not yet supported.

**A peer never appears.** Confirm the address is complete and ends in `.onion`.
The Sync tab reports how many entries it considered valid. If the peer requires
an access token, yours must match theirs exactly.

**Nothing downloads.** Confirm the peer has pressed START SHARING, that their
folder is not empty, and that *Only download setup files* is not filtering
everything out.

**Files stopped transferring after enabling antivirus.** Either install a
scanner or turn the setting back off — the Logs tab names the reason.

---

## Development

```bash
git clone https://github.com/nishizumi-maho/Nishizumi-Share.git
cd Nishizumi-Share
python -m pip install -r requirements-dev.txt
python -m pytest              # 230 tests
python -m nishizumi_share     # run the app
```

Everything except `nishizumi_share/ui` is Qt-free, so the network and security
core is testable headlessly.

| Module | Responsibility |
|---|---|
| `config.py` | Paths, settings validation and migration |
| `security.py` | Path safety, sanitisation, name mapping |
| `tor.py` | Tor process and control-port client |
| `server.py` | Flask routes and the controllable HTTP server |
| `syncclient.py` | Peer polling and downloading |
| `avscan.py` | Optional antivirus |
| `throttle.py` | Bandwidth and request limiting |
| `updater.py` | GitHub Releases updates |
| `controller.py` | Ties the above together |
| `ui/` | PyQt6 interface |

### Building the installer

On Windows, with [Inno Setup 6](https://jrsoftware.org/isdl.php) installed:

```powershell
pip install -r requirements-dev.txt
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
```

This downloads and verifies the Tor Expert Bundle, generates the icon, freezes
the app, compiles the installer into `packaging\output\`, and writes
`SHA256SUMS.txt`.

Tagging a release runs the same steps in CI and publishes the result:

```bash
git tag v3.0.1 && git push origin v3.0.1
```

The tag must match `nishizumi_share.__version__` or the build fails.

---

## Contributing

Issues and pull requests are welcome. Please keep the test suite green
(`python -m pytest`) and add tests for behaviour changes.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Provided for legitimate privacy and collaboration purposes. You are responsible
for complying with the laws that apply to you; Tor use is restricted in some
jurisdictions. The authors accept no liability for misuse.
