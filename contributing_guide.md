# Contributing to Nishizumi Share

Thank you for your interest in contributing! This document provides guidelines and technical details for contributors.

## Quick Links

- **Report bugs:** [GitHub Issues](https://github.com/nishizumi-maho/nishizumi-share/issues)
- **Suggest features:** Open an issue with `[Feature Request]` tag
- **Submit patches:** Pull requests welcome

## Project Structure

```
nishizumi-share/
├── teste.py           # Main application (full-featured)
├── Servidor.py        # Lite server (server-only)
├── cliente.py         # Lite client (client-only)
├── tor/               # Tor Expert Bundle (not in repo)
├── requirements.txt   # Python dependencies
├── README.md          # User documentation
├── INSTALL.md         # Installation guide
├── LICENSE            # MIT License
└── CONTRIBUTING.md    # This file
```

## Code Architecture

### Main Components

**teste.py** - Full Application
- `MainAppWindow` - PyQt6 UI with tabs (Client/Engineer/System)
- `TorManagerWorker` - Manages Tor process and hidden service
- `SwarmSyncWorker` - Client download worker
- `DataProtectionManager` - DLP sanitization
- Flask routes: `/list`, `/download/<map_id>/<fake_name>`

**Servidor.py** - Lite Server
- Simplified server-only variant
- Persistent onion identity
- Start with Windows support

**cliente.py** - Lite Client
- Client-only variant
- Embedded/external Tor support
- Tor bootstrap validation

### Key Security Components

1. **AV Scanning** (`av_scan_file`)
   - Windows: `MpCmdRun.exe`
   - Linux/macOS: ClamAV
   - 24h cache to avoid re-scanning

2. **Token Bucket** (`TokenBucket` class)
   - Smooth rate limiting
   - Prevents network congestion
   - Separate buckets for upload/download

3. **Path Safety** (`is_within_directory`)
   - Prevents directory traversal
   - Validates all file operations

4. **DLP Manager** (`DataProtectionManager`)
   - Sanitizes filenames
   - Generates deterministic fake names
   - HMAC-based mapping

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/nishizumi-share.git
cd nishizumi-share
git remote add upstream https://github.com/nishizumi-maho/nishizumi-share.git
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
pip install pytest black flake8  # Dev tools
```

### 4. Setup Tor

Place Tor Expert Bundle in `tor/` folder (see INSTALL.md)

### 5. Run Tests

```bash
# Manual testing
python teste.py

# Check for issues
flake8 *.py --max-line-length=120
```

## Making Changes

### 1. Create Branch

```bash
git checkout -b feature/your-feature-name
# OR
git checkout -b fix/bug-description
```

### 2. Code Guidelines

**Style:**
- Follow PEP 8 (use `black` for formatting)
- Max line length: 120 characters
- Use type hints where practical
- Document complex functions

**Example:**
```python
def av_scan_file(path: str, force_scan: bool = False) -> tuple[bool, str]:
    """
    Scan file with antivirus.
    
    Args:
        path: Absolute path to file
        force_scan: If True, block on scanner unavailable
        
    Returns:
        (clean_bool, reason_string)
    """
    # Implementation
```

**Security:**
- Always validate paths with `is_within_directory`
- Use `secrets` module for tokens (not `random`)
- Set restrictive file permissions (0o600)
- Never log sensitive data (use `mask_name` for filenames)

**UI:**
- Use PyQt6 signals for thread communication
- Keep UI responsive (no blocking operations)
- Provide user feedback (progress bars, logs)

### 3. Test Your Changes

**Manual Testing Checklist:**
- [ ] Windows + Defender scanning
- [ ] Linux + ClamAV scanning
- [ ] Embedded Tor works
- [ ] External Tor works
- [ ] Client downloads correctly
- [ ] Server serves correctly
- [ ] Rate limiting prevents abuse
- [ ] DLP rules apply
- [ ] Path traversal blocked

**Test with Real Setups:**
1. Run server on one machine
2. Run client on another
3. Share .onion URL
4. Verify files sync correctly

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add feature description"
# OR
git commit -m "fix: bug description"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `style:` Formatting changes
- `refactor:` Code restructuring
- `perf:` Performance improvement
- `test:` Adding tests
- `chore:` Maintenance tasks

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then open Pull Request on GitHub with:
- Clear description of changes
- Testing performed
- Screenshots (if UI changes)

## Areas for Contribution

### High Priority

- [ ] Unit tests (pytest)
- [ ] File versioning/conflict resolution
- [ ] Encryption at rest
- [ ] Per-user rate limiting
- [ ] Bidirectional sync
- [ ] Progress persistence (resume downloads)

### Medium Priority

- [ ] GUI themes/dark mode
- [ ] Notification system
- [ ] Bandwidth monitoring graphs
- [ ] Multi-language support (i18n)
- [ ] MacOS app bundle
- [ ] Better error recovery

### Documentation

- [ ] Video tutorial
- [ ] Common issues wiki
- [ ] API documentation
- [ ] Architecture diagrams
- [ ] Translation to other languages

### Platform Support

- [ ] Docker container
- [ ] Snap package (Linux)
- [ ] Homebrew formula (macOS)
- [ ] Windows installer (MSI)
- [ ] systemd service files

## Technical Details

### Tor Integration

**Hidden Service Creation:**
```python
# ADD_ONION via ControlPort
sock.sendall(f"ADD_ONION NEW:ED25519-V3 Port=80,{FLASK_PORT}\r\n")
# Response contains ServiceID (onion address) and PrivateKey
```

**Client Connection:**
```python
# SOCKS5h preserves .onion (DNS resolved by Tor)
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
requests.get(url, proxies=proxies)
```

### Ephemeral Mapping System

**Why Ephemeral:**
- Prevents long-lived file paths from leaking
- Token expires after 10 minutes
- Each `/list` call creates new snapshot

**Flow:**
1. Client calls `/list`
2. Server generates `map_id` and `map_token`
3. Server creates `{map_id: {fake_name: real_path}}`
4. Client uses token in `Authorization: Bearer <token>`
5. Server validates token and serves real file

### Rate Limiting Strategy

**Global Bucket (Server):**
- Tor hidden services see all clients as localhost
- Cannot rate-limit per IP
- Use global bucket: max 600 requests/min
- Generous limit to avoid false positives

**Per-Connection Bucket (Client):**
- Each download gets own bucket
- Prevents single fast connection from monopolizing bandwidth
- Smooth token refill avoids bursts

### AV Scanning Cache

**Cache Key:** SHA256 of file content

**Why Cache:**
- Scanning is slow (5-60 seconds)
- Same file shouldn't be re-scanned
- 24h TTL balances performance vs security

**Implementation:**
```python
_scan_cache = {
    "sha256_hash": {
        "clean": True,
        "reason": "defender_clean",
        "ts": 1704067200
    }
}
```

## Security Considerations

### Threat Model

**Protected Against:**
- IP address leakage (Tor)
- Directory traversal attacks
- Malware distribution (AV scanning)
- Data leaks in filenames (DLP)
- Rate-based DoS (token bucket)

**Not Protected Against:**
- End-to-end encryption (files sent plainly over Tor)
- Identity correlation (if onion shared publicly)
- Compromised endpoints
- Tor network analysis
- Timing attacks

### Responsible Disclosure

Found a security issue? Please:
1. Do NOT open public issue
2. Contact: GitHub Issues with `[SECURITY]` tag (do not include exploit details)
3. Wait for acknowledgment
4. Allow time for patch before disclosure

## Code of Conduct

- Be respectful and professional
- Welcome newcomers
- Focus on constructive feedback
- No discrimination or harassment
- Respect privacy and security

## Questions?

- Open an issue with `[Question]` tag
- Check existing issues first
- Provide context and code examples

## License

By contributing, you agree your contributions will be licensed under the MIT License.

---

Thank you for contributing to Nishizumi Share! 🧅🔒
