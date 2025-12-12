# Nishizumi Share

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/4951276a-0260-4565-b107-9673046bf23e" />

**Secure, anonymous file sharing over Tor hidden services**

Nishizumi Share is a privacy-focused file synchronization system designed for secure team collaboration. It uses Tor hidden services (.onion) to enable anonymous, peer-to-peer file sharing without exposing IP addresses or requiring central servers.

## Features

- 🧅 **Tor Hidden Services** - Complete anonymity via .onion addresses
- 🔒 **Optional Security** - Antivirus scanning can be enabled (Windows Defender/ClamAV)
- 🚦 **Rate Limiting** - Token bucket throttling to prevent network congestion
- 🔐 **Data Protection** - DLP rules for sanitizing sensitive filenames
- 🎫 **Ephemeral Tokens** - One-time access tokens for temporary sharing
- 💻 **Cross-Platform** - Windows, Linux, macOS support
- 🎨 **Clean UI** - PyQt6-based interface (Client/Engineer/System tabs)

## Use Cases

- **Racing Teams** - Share iRacing setups securely within your team
- **Private Collaboration** - Exchange files without cloud services
- **Anonymous Distribution** - Share content without revealing your location
- **Team Sync** - Keep setup files synchronized across team members

## Architecture

Nishizumi Share comes in two variants:

1. **Main Application** (`Main_full.py`) - Full-featured client + server with advanced DLP
2. **Lite Client** (`cliente.py`) - Lightweight client for downloads only

## Quick Start

### Prerequisites

```bash
# Python 3.10 or higher
python --version

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

- `PyQt6` - GUI framework
- `Flask` - HTTP server (Main app only)
- `waitress` - Production WSGI server (Main app only)
- `requests` - HTTP client
- `PySocks` - SOCKS proxy support

### Running the Main Application

```bash
python Main_full.py
```

**First-time setup:**

1. **System Tab**: Configure Tor
   - Check "Use embedded Tor" (place Tor Expert Bundle in `tor/` folder) — **Recommended**
   - OR specify path to external `tor.exe`
   - Click "START SERVER"

2. **Engineer Tab**: Share files
   - Select outgoing folder containing files to share
   - Copy your .onion URL and share with team

3. **Client Tab**: Download files
   - Set destination folder (e.g., `iRacing/setups/`)
   - Paste team member .onion URLs (one per line)
   - Choose sync mode (Smart Mode recommended)
   - Click "START SYNC"

### Running Lite Client

```bash
python cliente.py
```

1. Set destination folder
2. Enter team folder name
3. Add engineer .onion addresses
4. Choose Tor mode (embedded/external)
5. Check "Auto-start Tor if not running" (recommended)
6. Click "START TOR" then "START SYNC"

## How It Works

### Server Side (Main Application)

1. **Tor Service**: Creates a hidden service (.onion address)
2. **File Indexing**: Scans shared folder, creates ephemeral file mappings
3. **Optional AV Scanning**: Can scan files before serving (disabled by default)
4. **Rate Limiting**: Throttles uploads using token bucket algorithm
5. **Access Control**: Issues temporary tokens for each file list snapshot

### Client Side (Both Versions)

1. **Tor Connection**: Connects via SOCKS5h proxy (preserves .onion anonymity)
2. **Peer Discovery**: Fetches file lists from configured .onion peers
3. **Quarantine Download**: Downloads to `.quarantine` folder first
4. **Optional AV Scanning**: Main app can scan files (disabled by default); Lite client has no AV
5. **Atomic Move**: Moves files to final destination
6. **Continuous Sync**: Polls peers every 30 seconds for new files
7. **Clean Filenames**: Strips internal HMAC suffixes from saved files

## Security Features

### Antivirus Integration (Optional)

**Main Application:**
- AV scanning disabled by default (`AV_DISABLE_GLOBAL = True`)
- Can be enabled in System tab: "Force AV scan"
- **Windows**: Microsoft Defender (`MpCmdRun.exe`)
- **Linux/macOS**: ClamAV (`clamdscan` or `clamscan`)

**Lite Client:**
- No antivirus scanning (removed for simplicity)
- Files downloaded directly to destination after quarantine stage

### Data Leak Protection (DLP)

Create rules in `security_rules.txt`:
```
internal=PUBLIC
CompanyName=TEAM
secret=xxx
```

Files are sanitized and given deterministic fake names before sharing.

### Path Safety

- Strict directory traversal prevention
- All paths validated against base directory
- Quarantine folder with restricted permissions (0o700)

### Token System

- **Map Tokens**: Short-lived tokens (10 min) for file list access
- **One-Time Tokens**: UI-generated tokens for manual sharing
- **Authorization**: Bearer token required for all downloads

## Configuration

Settings stored in:
- **Windows**: `%APPDATA%\NishizumiShare\` (Main) or `%USERPROFILE%\.nishizumi-sync-client\` (Lite)
- **Linux/macOS**: `~/.nishizumishare/` (Main) or `~/.nishizumi-sync-client/` (Lite)

Key files:
- `settings.json` - User preferences
- `onion_private_key` - Persistent .onion identity (Main app only)
- `team_peers.txt` - Saved peer list (Main app)
- `security_rules.txt` - DLP rules (Main app)
- `scan_cache.json` - AV scan cache if enabled (Main app)

## Tor Setup

### Option 1: Embedded Tor (Recommended)

1. Download [Tor Expert Bundle](https://www.torproject.org/download/tor/)
2. Extract to `tor/` folder next to the Python script:
   ```
   nishizumi-share/
   ├── Main_full.py
   ├── cliente.py
   ├── tor/
   │   ├── tor.exe (Windows)
   │   └── tor (Linux/macOS)
   ```
3. Make sure `tor` binary is executable on Linux/macOS: `chmod +x tor/tor`

### Option 2: External Tor

Point to existing Tor installation:
- Windows: `C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- Linux: `/usr/bin/tor`

### Tor Process Management

**Main Application:**
- Tracks Tor process and terminates it when GUI closes
- Regenerating identity stops Tor automatically

**Lite Client:**
- Only stops Tor processes it started
- If SOCKS port already in use, assumes existing Tor is available
- Smart detection prevents duplicate Tor instances

## Advanced Usage

### Smart Mode vs Simple Mirror

**Smart Mode** (sync_mode: 3):
- Creates per-car folder structure
- Path: `iRacing/setups/[CAR]/Team_Setups/file.sto`
- Best for racing teams

**Simple Mirror** (sync_mode: 2):
- Mirrors source structure exactly
- Path: `iRacing/setups/Team_Setups/file.sto`

### Rate Limiting

Adjust in UI or `settings.json`:
```json
{
  "download_limit_bps": 2097152,  // 2 MB/s
  "upload_limit_bps": 2097152,    // 2 MB/s (Main app only)
  "max_file_size": 209715200      // 200 MB per file
}
```

### Regenerating Identity (Main App)

System Tab → "REGENERATE IDENTITY" button
- Deletes saved onion private key
- Stops Tor process if running
- New .onion address on next server start
- Share new address with team

### One-Time Sharing (Main App)

Engineer Tab → Generate ephemeral token:
1. Set TTL (time-to-live in minutes)
2. Click "Generate token"
3. Copy and share token via secure channel (DM)
4. Token works once or expires after TTL

## Troubleshooting

### "Tor path missing or invalid"
- Ensure `tor/` folder exists with tor executable
- Check file permissions (`chmod +x tor/tor` on Linux/macOS)
- Try external Tor mode

### "ControlPort not reachable" (Main App)
- Another Tor process may be using port 9051
- Kill existing Tor processes
- Change CTRL_PORT in code if needed

### "Tor did not bootstrap" (Lite Client)
- Check bundled tor exists in `tor/` folder
- Verify tor binary has execute permissions
- Check if another process is using SOCKS port 9050
- Try external Tor mode with path to working tor.exe

### "AV blocked file" (if AV enabled)
- Check file isn't actually infected
- Disable "Force AV scan" in System tab
- Update antivirus definitions
- Note: AV is disabled by default in v2.2.1+

### "Rate limit exceeded"
- Global rate limit protects against abuse
- Occurs if >600 requests in 60 seconds
- Wait and retry

### Downloads not starting
- Verify Tor is bootstrapped (check logs)
- Ensure peer .onion URLs are correct
- Check SOCKS proxy is working: `curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org`
- Look for "Bootstrapped 100%" in logs

### Files have strange names
- **Fixed in v2.2.1**: Client now automatically strips internal HMAC suffixes
- Files saved with clean, readable names
- Server still uses sanitized names internally for DLP

## Performance Tips

- Use embedded Tor for better reliability
- Adjust rate limits based on connection speed
- Enable AV scan cache (if using AV) to avoid re-scanning same files
- Use Smart Mode only when needed (Simple Mirror is faster)
- Lite client has lower overhead than Main app for download-only scenarios

## Security Recommendations

1. **Keep identities private** - Never share .onion URLs publicly
2. **Verify team members** - Confirm .onion addresses through trusted channels
3. **Use DLP rules** - Sanitize sensitive information in filenames
4. **Consider AV scanning** - Enable if downloading from untrusted sources
5. **Regenerate identity** - If .onion is compromised, regenerate immediately
6. **Secure host** - Run on trusted, malware-free systems
7. **Monitor logs** - Check for suspicious activity or failed auth attempts

## Known Limitations

- No file versioning or conflict resolution
- No encryption at rest (files stored plainly after download)
- Tor introduces latency (~2-10 seconds per request)
- Global rate limiting (not per-user in onion context)
- No bidirectional sync (client downloads only)
- Lite client lacks server functionality

## Version History

### v2.2.1 (Current)
- **Main App**: AV scanning disabled by default (configurable)
- **Main App**: Client strips HMAC suffix from filenames automatically
- **Main App**: Improved Tor process management and cleanup
- **Lite Client**: AV completely removed for simplicity
- **Lite Client**: Smart Tor detection (won't start duplicate if already running)
- **Lite Client**: Clean filename handling
- **Both**: More robust bootstrap detection
- **Both**: Better error handling for edge cases

### v2.1.x
- Initial public release
- Full DLP implementation
- Ephemeral token system

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/nishizumi-maho/nishizumi-share.git
cd nishizumi-share

# Install dependencies
pip install -r requirements.txt

# Run Main Application
python Main_full.py

# OR Run Lite Client
python cliente.py
```

### Creating Executables

```bash
pip install pyinstaller

# Main Application
# Windows
pyinstaller --onefile --windowed --add-data "tor;tor" Main_full.py

# Linux/macOS
pyinstaller --onefile --windowed --add-data "tor:tor" Main_full.py

# Lite Client
# Windows
pyinstaller --onefile --windowed --add-data "tor;tor" cliente.py

# Linux/macOS
pyinstaller --onefile --windowed --add-data "tor:tor" cliente.py
```

## Contributing

Issues and pull requests welcome! Please:
- Follow existing code style
- Test on Windows + Linux if possible
- Update documentation for new features
- Test both Main app and Lite client if changes affect both

Report issues: https://github.com/nishizumi-maho/nishizumi-share/issues

## License

MIT License - See [LICENSE](LICENSE) file

## Disclaimer

This software is provided for legitimate privacy and collaboration purposes. Users are responsible for compliance with local laws. The authors assume no liability for misuse.

Tor usage may be restricted in some jurisdictions. Consult local regulations before use.

**Privacy Notice**: By default, antivirus scanning is disabled to maximize privacy and reduce dependencies. Enable it in settings if needed for your use case.

## Credits

Developed by nishizumi-maho  
GitHub: [@nishizumi-maho](https://github.com/nishizumi-maho)

Built with: Python, PyQt6, Flask, Tor, Waitress

---

**Stay anonymous. Share securely.** 🧅🔒
