# Installation Guide

## Prerequisites

### 1. Python 3.10+

**Windows:**
- Download from [python.org](https://www.python.org/downloads/)
- Check "Add Python to PATH" during installation

**Linux:**
```bash
sudo apt update
sudo apt install python3 python3-pip  # Debian/Ubuntu
# OR
sudo dnf install python3 python3-pip  # Fedora
```

**macOS:**
```bash
brew install python3
```

### 2. Tor (Choose One Option)

#### Option A: Embedded Tor (Recommended)

1. Download **Tor Expert Bundle** from [torproject.org](https://www.torproject.org/download/tor/)
2. Extract and place in `tor/` folder:

```
nishizumi-share/
├── teste.py
├── Servidor.py
├── cliente.py
├── tor/
│   ├── tor.exe (Windows)
│   ├── tor (Linux/macOS)
│   ├── libevent-*.dll (Windows)
│   └── ... (other Tor files)
```

**Linux/macOS:** Make executable
```bash
chmod +x tor/tor
```

#### Option B: System Tor

**Windows:**
- Install Tor Browser
- Point to: `C:\...\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

**Linux:**
```bash
sudo apt install tor  # Debian/Ubuntu
sudo dnf install tor  # Fedora
```

**macOS:**
```bash
brew install tor
```

### 3. Antivirus Scanner

**Windows:** Built-in (Windows Defender - automatic)

**Linux:**
```bash
sudo apt install clamav clamav-daemon
sudo freshclam  # Update virus definitions
sudo systemctl start clamav-daemon
```

**macOS:**
```bash
brew install clamav
freshclam  # Update definitions
```

## Installation Steps

### 1. Clone Repository

```bash
git clone https://github.com/nishizumi-maho/nishizumi-share.git
cd nishizumi-share
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**If pip fails:**
```bash
# Windows
python -m pip install -r requirements.txt

# Linux/macOS - use pip3 if needed
pip3 install -r requirements.txt
```

### 3. Verify Installation

```bash
# Test imports
python -c "import PyQt6, flask, requests; print('All dependencies OK')"

# Check Tor
./tor/tor --version  # Linux/macOS
tor\tor.exe --version  # Windows
```

## First Run

### Main Application

```bash
python teste.py
```

1. Go to **System** tab
2. Check "Use embedded Tor"
3. Click **START SERVER**
4. Wait for "Onion ready" message

### Lite Server

```bash
python Servidor.py
```

1. Select share folder
2. Check "Use Embedded Tor"
3. Click **START SERVER**

### Lite Client

```bash
python cliente.py
```

1. Set destination folder
2. Check "Use embedded Tor"
3. Click **START TOR**
4. Add peer .onion URLs
5. Click **START SYNC**

## Platform-Specific Notes

### Windows

**Firewall:** Allow Python through Windows Firewall when prompted

**Antivirus:** Windows Defender is automatic - no setup needed

**Start with Windows:** Enable in app settings (adds registry entry)

### Linux

**Permissions:** Ensure execute bit on tor binary
```bash
chmod +x tor/tor
```

**ClamAV:** Start daemon for faster scans
```bash
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
```

**AppArmor/SELinux:** May need to allow Tor network access

### macOS

**Gatekeeper:** First run may require "Allow" in Security & Privacy settings

**Permissions:** Grant network permissions when prompted

**ClamAV:** Run `freshclam` regularly to update definitions

## Troubleshooting Installation

### "No module named 'PyQt6'"
```bash
pip install --upgrade pip
pip install PyQt6
```

### "Tor not found"
- Verify `tor/` folder exists next to Python scripts
- Check executable permissions (`chmod +x` on Linux/macOS)
- Try system Tor as fallback

### "Permission denied" on Linux
```bash
# Make scripts executable
chmod +x *.py

# Fix tor permissions
chmod +x tor/tor
```

### Python version too old
```bash
python --version  # Should be 3.10+

# Use python3 explicitly if needed
python3 teste.py
```

### ClamAV not scanning
```bash
# Update definitions
sudo freshclam

# Test manually
clamscan --version
clamscan /path/to/test/file
```

## Building Standalone Executables

### PyInstaller Setup

```bash
pip install pyinstaller
```

### Build Commands

**Windows:**
```bash
pyinstaller --onefile --windowed --add-data "tor;tor" --name "NishizumiShare" teste.py
```

**Linux:**
```bash
pyinstaller --onefile --windowed --add-data "tor:tor" --name "NishizumiShare" teste.py
```

**macOS:**
```bash
pyinstaller --onefile --windowed --add-data "tor:tor" --name "NishizumiShare" teste.py
```

Output: `dist/NishizumiShare.exe` (Windows) or `dist/NishizumiShare` (Linux/macOS)

## Uninstallation

### Remove Application

```bash
# Delete repository
rm -rf nishizumi-share/

# Remove Python packages (optional)
pip uninstall PyQt6 Flask waitress requests PySocks
```

### Remove Configuration

**Windows:**
```
Delete: %APPDATA%\NishizumiShare\
```

**Linux/macOS:**
```bash
rm -rf ~/.nishizumishare/
```

### Remove Start with System (Windows)

1. Press Win+R
2. Type `shell:startup`
3. Delete Nishizumi Share shortcut

OR remove registry entry:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Delete: NishizumiShare
```

## Next Steps

- Read [README.md](README.md) for usage instructions
- Configure DLP rules in `security_rules.txt`
- Share your .onion URL with team members
- Join development at https://github.com/nishizumi-maho/nishizumi-share

## Getting Help

**Issues:** https://github.com/nishizumi-maho/nishizumi-share/issues

**Tor Support:** https://support.torproject.org/

**Python Help:** https://www.python.org/about/help/
