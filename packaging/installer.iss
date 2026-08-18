; Inno Setup script — builds the single setup installer for Nishizumi Share.
;
; The installer is per-user (PrivilegesRequired=lowest) on purpose: the in-app
; updater runs it silently, and a per-user install needs no UAC prompt, so
; unattended updates actually complete.
;
; Build:
;   iscc /DMyAppVersion=3.0.0 packaging\installer.iss

#ifndef MyAppVersion
  #define MyAppVersion "3.0.0"
#endif

#define MyAppName "Nishizumi Share"
#define MyAppShortName "NishizumiShare"
#define MyAppPublisher "nishizumi-maho"
#define MyAppURL "https://github.com/nishizumi-maho/Nishizumi-Share"
#define MyAppExeName "NishizumiShare.exe"

[Setup]
; Stable AppId: keeps upgrades in place instead of installing side by side.
AppId={{8E5A9D34-6C1B-4B27-9F2E-7A4D5C8B1E90}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
VersionInfoVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=output
OutputBaseFilename={#MyAppShortName}-Setup-{#MyAppVersion}
SetupIconFile=app.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

; Per-user install so the updater can run silently without elevation.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; Let the installer replace files that are in use during an update.
CloseApplications=yes
RestartApplications=yes
CloseApplicationsFilter=*.exe,*.dll,*.pyd

UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startupicon"; Description: "Start {#MyAppName} when I sign in"; GroupDescription: "Startup"; Flags: unchecked

[Files]
; The whole PyInstaller one-folder output, including the bundled tor\ folder.
Source: "..\dist\NishizumiShare\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
; /RESTARTAPPLICATIONS relaunches the app after a silent update; skip the
; "launch now" prompt in that case.
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove downloaded installers, but leave the user's settings and onion key
; alone so reinstalling keeps their identity.
Type: filesandordirs; Name: "{userappdata}\{#MyAppShortName}\updates"
