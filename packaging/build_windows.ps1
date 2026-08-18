<#
.SYNOPSIS
    Builds the single Nishizumi Share setup installer on Windows.

.DESCRIPTION
    Runs the whole chain: fetch Tor, generate the icon, freeze with
    PyInstaller, compile the Inno Setup installer, and write SHA256SUMS.txt.
    The checksum file is what the in-app updater verifies against, so it is
    part of the build, not an afterthought.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1 -Version 3.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$TorVersion = "",
    [switch]$SkipTor
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$PackagingDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $PackagingDir
Push-Location $RepoRoot

try {
    if (-not $Version) {
        $Version = (python -c "import nishizumi_share; print(nishizumi_share.__version__)").Trim()
    }
    Write-Host "== Building Nishizumi Share $Version ==" -ForegroundColor Cyan

    # 1. Bundled Tor -------------------------------------------------------
    if (-not $SkipTor) {
        Write-Host "`n[1/5] Fetching Tor Expert Bundle" -ForegroundColor Yellow
        $torArgs = @("packaging/fetch_tor.py")
        if ($TorVersion) { $torArgs += @("--version", $TorVersion) }
        python @torArgs
        if ($LASTEXITCODE -ne 0) { throw "Tor download failed" }
    } else {
        Write-Host "`n[1/5] Skipping Tor download (-SkipTor)" -ForegroundColor DarkYellow
    }

    # 2. Icon --------------------------------------------------------------
    Write-Host "`n[2/5] Generating icon" -ForegroundColor Yellow
    python packaging/generate_icon.py
    if ($LASTEXITCODE -ne 0) { throw "Icon generation failed" }

    # 3. Freeze ------------------------------------------------------------
    Write-Host "`n[3/5] Freezing with PyInstaller" -ForegroundColor Yellow
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist")  { Remove-Item -Recurse -Force "dist" }

    pyinstaller --noconfirm --clean packaging/nishizumi_share.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

    $exePath = "dist\NishizumiShare\NishizumiShare.exe"
    if (-not (Test-Path $exePath)) { throw "Expected $exePath to exist" }

    if (-not (Test-Path "dist\NishizumiShare\_internal\tor\tor.exe") -and
        -not (Test-Path "dist\NishizumiShare\tor\tor.exe")) {
        Write-Warning "No bundled tor.exe in the frozen output"
    }

    # 4. Installer ---------------------------------------------------------
    Write-Host "`n[4/5] Compiling the installer" -ForegroundColor Yellow
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if (-not $iscc) {
        foreach ($candidate in @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
        )) {
            if (Test-Path $candidate) { $iscc = $candidate; break }
        }
    }
    if (-not $iscc) { throw "Inno Setup (ISCC.exe) not found. Install Inno Setup 6." }

    & $iscc "/DMyAppVersion=$Version" "packaging\installer.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

    # 5. Checksums ---------------------------------------------------------
    Write-Host "`n[5/5] Writing SHA256SUMS.txt" -ForegroundColor Yellow
    $outputDir = Join-Path $PackagingDir "output"
    $installer = Get-ChildItem -Path $outputDir -Filter "NishizumiShare-Setup-*.exe" |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $installer) { throw "No installer produced in $outputDir" }

    $hash = (Get-FileHash -Algorithm SHA256 -Path $installer.FullName).Hash.ToLower()
    # Trailing newline keeps the file compatible with `sha256sum -c`.
    "$hash  $($installer.Name)`n" | Set-Content -Path (Join-Path $outputDir "SHA256SUMS.txt") -Encoding ascii -NoNewline

    Write-Host "`nInstaller: $($installer.FullName)" -ForegroundColor Green
    Write-Host "SHA-256  : $hash" -ForegroundColor Green
    Write-Host "Size     : $([math]::Round($installer.Length / 1MB, 1)) MB" -ForegroundColor Green
}
finally {
    Pop-Location
}
