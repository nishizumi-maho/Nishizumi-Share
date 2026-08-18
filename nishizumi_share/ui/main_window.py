"""Main application window."""

from __future__ import annotations

import logging
import os
import sys
from typing import List, Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QDesktopServices, QFont
from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .. import DISPLAY_NAME, GITHUB_REPO, __version__
from ..config import Settings, get_paths
from ..controller import ControllerError, ServiceController
from ..desktop import autostart_supported, get_autostart, open_path
from ..logging_setup import QtLogBridge, configure_logging
from ..security import load_dlp_rules, parse_dlp_rules, save_dlp_rules
from ..syncclient import normalise_peer_url
from ..tor import find_bundled_tor, find_system_tor, socks_proxies
from ..updater import UpdateError, UpdateInfo, Updater, check_in_background
from .widgets import BackgroundTask, PathPicker, SignalBridge, StatusBanner

logger = logging.getLogger(__name__)

MAX_LOG_BLOCKS = 2000

SYNC_MODE_LABELS = [
    ("smart", "Smart — one folder per car (recommended for iRacing)"),
    ("mirror", "Mirror — team folder containing the peer's tree"),
    ("flat", "Exact — reproduce the peer's tree as-is"),
]


class MainWindow(QWidget):
    """Single window with Sync, Share, Settings and Logs tabs."""

    def __init__(self, settings: Optional[Settings] = None):
        super().__init__()

        self.settings = settings or Settings.load()
        self.paths = get_paths()
        self.bridge = SignalBridge()
        self._tasks: List[BackgroundTask] = []
        self._pending_update: Optional[UpdateInfo] = None
        self._served_count = 0

        self.controller = ServiceController(
            self.settings,
            on_log=self.bridge.log.emit,
            on_progress=self.bridge.progress.emit,
            on_security_alert=self.bridge.alert.emit,
            on_file_served=self.bridge.file_served.emit,
        )

        self.setWindowTitle(f"{DISPLAY_NAME} — v{__version__}")
        self.resize(1000, 780)

        self._build_ui()
        self._connect_signals()
        self._load_settings_into_ui()

        # Mirror library logging into the Logs tab.
        logging.getLogger().addHandler(QtLogBridge(lambda text, level: self.bridge.log.emit(text)))

        if self.settings.get("auto_check_updates"):
            QTimer.singleShot(3000, lambda: self._check_updates(silent=True))

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self.banner = StatusBanner()
        layout.addWidget(self.banner)

        self.update_banner = QLabel()
        self.update_banner.setOpenExternalLinks(True)
        self.update_banner.setWordWrap(True)
        self.update_banner.setStyleSheet(
            "background:#1e3a5f; color:#e8f0ff; padding:8px; border-radius:6px;"
        )
        self.update_banner.hide()
        layout.addWidget(self.update_banner)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_sync_tab(), "Sync")
        self.tabs.addTab(self._build_share_tab(), "Share")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_logs_tab(), "Logs")
        layout.addWidget(self.tabs, stretch=1)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)

    # -- Sync tab ------------------------------------------------------

    def _build_sync_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        layout.addWidget(QLabel("<b>1. Where downloaded files are saved</b>"))
        self.dest_picker = PathPicker("Select the destination folder (e.g. iRacing/setups)")
        layout.addWidget(self.dest_picker)

        layout.addWidget(QLabel("<b>2. Team peers — one .onion address per line</b>"))
        self.peers_edit = QPlainTextEdit()
        self.peers_edit.setPlaceholderText("http://xxxxxxxx….onion")
        self.peers_edit.setMinimumHeight(110)
        layout.addWidget(self.peers_edit)

        self.peers_status = QLabel()
        self.peers_status.setStyleSheet("color:#999;")
        layout.addWidget(self.peers_status)

        group = QGroupBox("How downloads are organised")
        form = QFormLayout(group)

        self.sync_mode_combo = QComboBox()
        for value, label in SYNC_MODE_LABELS:
            self.sync_mode_combo.addItem(label, value)
        form.addRow("Layout:", self.sync_mode_combo)

        self.team_edit = QLineEdit()
        form.addRow("Team folder name:", self.team_edit)

        self.only_setups_check = QCheckBox("Only download setup files (.sto, .olap, .blap, .rpy)")
        form.addRow("", self.only_setups_check)

        self.preview_label = QLabel()
        self.preview_label.setStyleSheet("color:#8ab4f8;")
        form.addRow("Preview:", self.preview_label)

        layout.addWidget(group)

        controls = QHBoxLayout()
        self.btn_sync = QPushButton("START SYNC")
        self.btn_sync.setMinimumHeight(40)
        controls.addWidget(self.btn_sync)

        self.btn_open_dest = QPushButton("Open destination folder")
        controls.addWidget(self.btn_open_dest)
        layout.addLayout(controls)

        layout.addStretch(1)
        return tab

    # -- Share tab -----------------------------------------------------

    def _build_share_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        layout.addWidget(QLabel("<b>1. Folder to share with your team</b>"))
        self.share_picker = PathPicker("Select the folder whose files you want to share")
        layout.addWidget(self.share_picker)

        controls = QHBoxLayout()
        self.btn_share = QPushButton("START SHARING")
        self.btn_share.setMinimumHeight(40)
        controls.addWidget(self.btn_share)
        layout.addLayout(controls)

        layout.addWidget(QLabel("<b>2. Your .onion address — send this to your team</b>"))
        onion_row = QHBoxLayout()
        self.onion_edit = QLineEdit()
        self.onion_edit.setReadOnly(True)
        self.onion_edit.setPlaceholderText("Available once sharing has started")
        font = QFont("monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.onion_edit.setFont(font)
        self.btn_copy_onion = QPushButton("Copy")
        onion_row.addWidget(self.onion_edit, stretch=1)
        onion_row.addWidget(self.btn_copy_onion)
        layout.addLayout(onion_row)

        self.served_label = QLabel("Files served: 0")
        layout.addWidget(self.served_label)

        # -- access control
        access_group = QGroupBox("Access control")
        access_form = QFormLayout(access_group)

        self.require_token_check = QCheckBox(
            "Require an access token before listing files (share it with your team)"
        )
        access_form.addRow("", self.require_token_check)

        token_row = QHBoxLayout()
        self.access_token_edit = QLineEdit()
        self.access_token_edit.setPlaceholderText("Shared secret")
        self.btn_new_access_token = QPushButton("Generate")
        token_row.addWidget(self.access_token_edit, stretch=1)
        token_row.addWidget(self.btn_new_access_token)
        token_widget = QWidget()
        token_widget.setLayout(token_row)
        access_form.addRow("Access token:", token_widget)

        layout.addWidget(access_group)

        # -- one time tokens
        onetime_group = QGroupBox("One-time share link")
        onetime_form = QFormLayout(onetime_group)

        self.token_ttl_spin = QSpinBox()
        self.token_ttl_spin.setRange(1, 10080)
        self.token_ttl_spin.setValue(60)
        self.token_ttl_spin.setSuffix(" min")
        onetime_form.addRow("Valid for:", self.token_ttl_spin)

        onetime_row = QHBoxLayout()
        self.btn_gen_token = QPushButton("Generate one-time token")
        self.onetime_token_edit = QLineEdit()
        self.onetime_token_edit.setReadOnly(True)
        self.btn_copy_onetime = QPushButton("Copy")
        onetime_row.addWidget(self.btn_gen_token)
        onetime_row.addWidget(self.onetime_token_edit, stretch=1)
        onetime_row.addWidget(self.btn_copy_onetime)
        onetime_widget = QWidget()
        onetime_widget.setLayout(onetime_row)
        onetime_form.addRow("", onetime_widget)

        layout.addWidget(onetime_group)

        # -- DLP
        dlp_group = QGroupBox("Filename privacy rules (DLP)")
        dlp_layout = QVBoxLayout(dlp_group)
        dlp_layout.addWidget(
            QLabel(
                "One rule per line, <code>secret=PUBLIC</code>. Matching text is "
                "replaced in the names your peers see."
            )
        )
        self.dlp_edit = QPlainTextEdit()
        self.dlp_edit.setPlaceholderText("internal=PUBLIC\nMyTeamName=TEAM")
        self.dlp_edit.setMaximumHeight(120)
        dlp_layout.addWidget(self.dlp_edit)
        self.btn_save_dlp = QPushButton("Save rules")
        dlp_layout.addWidget(self.btn_save_dlp)
        layout.addWidget(dlp_group)

        layout.addStretch(1)
        return tab

    # -- Settings tab --------------------------------------------------

    def _build_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Tor
        tor_group = QGroupBox("Tor")
        tor_form = QFormLayout(tor_group)

        self.tor_mode_combo = QComboBox()
        self.tor_mode_combo.addItem("Bundled Tor (recommended)", "embedded")
        self.tor_mode_combo.addItem("External Tor executable", "external")
        tor_form.addRow("Tor source:", self.tor_mode_combo)

        self.tor_path_picker = PathPicker(
            "Path to the tor executable",
            directory=False,
            file_filter="Tor executable (tor.exe tor);;All files (*)",
        )
        tor_form.addRow("External path:", self.tor_path_picker)

        self.tor_detect_label = QLabel()
        self.tor_detect_label.setStyleSheet("color:#999;")
        self.tor_detect_label.setWordWrap(True)
        tor_form.addRow("Detected:", self.tor_detect_label)

        self.socks_port_spin = self._port_spin()
        tor_form.addRow("SOCKS port:", self.socks_port_spin)
        self.control_port_spin = self._port_spin()
        tor_form.addRow("Control port:", self.control_port_spin)

        layout.addWidget(tor_group)

        # Bandwidth
        bw_group = QGroupBox("Bandwidth and limits")
        bw_form = QFormLayout(bw_group)

        self.dl_limit_spin = QSpinBox()
        self.dl_limit_spin.setRange(0, 1024 * 1024)
        self.dl_limit_spin.setSuffix(" KB/s")
        self.dl_limit_spin.setSpecialValueText("Unlimited")
        bw_form.addRow("Download limit:", self.dl_limit_spin)

        self.ul_limit_spin = QSpinBox()
        self.ul_limit_spin.setRange(0, 1024 * 1024)
        self.ul_limit_spin.setSuffix(" KB/s")
        self.ul_limit_spin.setSpecialValueText("Unlimited")
        bw_form.addRow("Upload limit:", self.ul_limit_spin)

        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 8192)
        self.max_size_spin.setSuffix(" MB")
        bw_form.addRow("Max file size:", self.max_size_spin)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(5, 3600)
        self.interval_spin.setSuffix(" s")
        bw_form.addRow("Sync interval:", self.interval_spin)

        layout.addWidget(bw_group)

        # Antivirus
        av_group = QGroupBox("Antivirus (optional)")
        av_layout = QVBoxLayout(av_group)
        self.av_enabled_check = QCheckBox(
            "Scan files with the system antivirus (Microsoft Defender / ClamAV)"
        )
        self.av_block_check = QCheckBox(
            "Block transfers when no antivirus is available (fail closed)"
        )
        av_layout.addWidget(self.av_enabled_check)
        av_layout.addWidget(self.av_block_check)
        layout.addWidget(av_group)

        # Updates
        update_group = QGroupBox("Updates")
        update_layout = QVBoxLayout(update_group)
        self.auto_update_check = QCheckBox("Check for updates automatically at start-up")
        self.update_tor_check = QCheckBox("Route update checks through Tor")
        self.prerelease_check = QCheckBox("Include pre-release versions")
        update_layout.addWidget(self.auto_update_check)
        update_layout.addWidget(self.update_tor_check)
        update_layout.addWidget(self.prerelease_check)

        update_row = QHBoxLayout()
        self.btn_check_updates = QPushButton("Check for updates now")
        self.version_label = QLabel(f"Installed version: {__version__}")
        update_row.addWidget(self.btn_check_updates)
        update_row.addWidget(self.version_label)
        update_row.addStretch(1)
        update_layout.addLayout(update_row)
        layout.addWidget(update_group)

        # System
        system_group = QGroupBox("System")
        system_layout = QVBoxLayout(system_group)
        self.autostart_check = QCheckBox("Start automatically when I sign in")
        self.autostart_check.setEnabled(autostart_supported())
        if not autostart_supported():
            self.autostart_check.setToolTip("Not supported on this platform")
        system_layout.addWidget(self.autostart_check)

        folder_row = QHBoxLayout()
        self.btn_open_config = QPushButton("Open settings folder")
        self.btn_open_logs = QPushButton("Open log folder")
        folder_row.addWidget(self.btn_open_config)
        folder_row.addWidget(self.btn_open_logs)
        folder_row.addStretch(1)
        system_layout.addLayout(folder_row)

        danger_row = QHBoxLayout()
        self.btn_burn = QPushButton("Reset .onion identity")
        self.btn_burn.setStyleSheet("color:#c62828;")
        danger_row.addWidget(self.btn_burn)
        danger_row.addStretch(1)
        system_layout.addLayout(danger_row)

        layout.addWidget(system_group)

        self.btn_save_settings = QPushButton("SAVE SETTINGS")
        self.btn_save_settings.setMinimumHeight(36)
        layout.addWidget(self.btn_save_settings)

        layout.addStretch(1)
        return tab

    @staticmethod
    def _port_spin() -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(1, 65535)
        return spin

    # -- Logs tab ------------------------------------------------------

    def _build_logs_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.document().setMaximumBlockCount(MAX_LOG_BLOCKS)
        self.log_view.setStyleSheet(
            "background:#101418; color:#b8e6b8; font-family:monospace;"
        )
        layout.addWidget(self.log_view, stretch=1)

        row = QHBoxLayout()
        self.btn_copy_log = QPushButton("Copy log")
        self.btn_clear_log = QPushButton("Clear")
        row.addWidget(self.btn_copy_log)
        row.addWidget(self.btn_clear_log)
        row.addStretch(1)
        layout.addLayout(row)

        return tab

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------

    def _connect_signals(self) -> None:
        self.bridge.log.connect(self.append_log)
        self.bridge.progress.connect(self._on_progress)
        self.bridge.alert.connect(self._on_security_alert)
        self.bridge.file_served.connect(self._on_file_served)

        self.btn_sync.clicked.connect(self._toggle_sync)
        self.btn_share.clicked.connect(self._toggle_share)
        self.btn_open_dest.clicked.connect(
            lambda: self._open_folder(self.dest_picker.text(), "destination")
        )
        self.btn_copy_onion.clicked.connect(
            lambda: self._copy(self.onion_edit.text(), "Onion address copied")
        )
        self.btn_gen_token.clicked.connect(self._generate_one_time_token)
        self.btn_copy_onetime.clicked.connect(
            lambda: self._copy(self.onetime_token_edit.text(), "Token copied")
        )
        self.btn_new_access_token.clicked.connect(self._generate_access_token)
        self.btn_save_dlp.clicked.connect(self._save_dlp_rules)

        self.btn_save_settings.clicked.connect(self._save_settings_from_ui)
        self.btn_check_updates.clicked.connect(lambda: self._check_updates(silent=False))
        self.btn_open_config.clicked.connect(lambda: self._open_folder(str(self.paths.root), "settings"))
        self.btn_open_logs.clicked.connect(lambda: self._open_folder(str(self.paths.logs), "log"))
        self.btn_burn.clicked.connect(self._burn_identity)

        self.btn_copy_log.clicked.connect(
            lambda: self._copy(self.log_view.toPlainText(), "Log copied")
        )
        self.btn_clear_log.clicked.connect(self.log_view.clear)

        self.tor_mode_combo.currentIndexChanged.connect(self._update_tor_controls)
        self.sync_mode_combo.currentIndexChanged.connect(self._update_preview)
        self.team_edit.textChanged.connect(self._update_preview)
        self.peers_edit.textChanged.connect(self._update_peer_status)
        self.require_token_check.toggled.connect(self.access_token_edit.setEnabled)
        self.av_enabled_check.toggled.connect(self.av_block_check.setEnabled)

    # ------------------------------------------------------------------
    # Settings <-> UI
    # ------------------------------------------------------------------

    def _load_settings_into_ui(self) -> None:
        settings = self.settings

        self.dest_picker.setText(str(settings.get("save_dir") or ""))
        self.share_picker.setText(str(settings.get("share_dir") or ""))
        self.peers_edit.setPlainText("\n".join(settings.get("peers") or []))
        self.team_edit.setText(str(settings.get("team_folder") or "Team_Setups"))
        self.only_setups_check.setChecked(bool(settings.get("only_setup_files")))

        self._select_by_data(self.sync_mode_combo, settings.get("sync_mode"))
        self._select_by_data(self.tor_mode_combo, settings.get("tor_mode"))

        self.tor_path_picker.setText(str(settings.get("tor_path") or ""))
        self.socks_port_spin.setValue(int(settings.get("socks_port") or 9050))
        self.control_port_spin.setValue(int(settings.get("control_port") or 9051))

        self.dl_limit_spin.setValue(int(settings.get("download_limit_bps") or 0) // 1024)
        self.ul_limit_spin.setValue(int(settings.get("upload_limit_bps") or 0) // 1024)
        self.max_size_spin.setValue(max(1, int(settings.get("max_file_size") or 0) // (1024 * 1024)))
        self.interval_spin.setValue(int(settings.get("sync_interval_seconds") or 30))

        self.av_enabled_check.setChecked(bool(settings.get("av_enabled")))
        self.av_block_check.setChecked(bool(settings.get("av_block_when_unavailable")))
        self.av_block_check.setEnabled(self.av_enabled_check.isChecked())

        self.require_token_check.setChecked(bool(settings.get("require_list_token")))
        self.access_token_edit.setText(str(settings.get("list_access_token") or ""))
        self.access_token_edit.setEnabled(self.require_token_check.isChecked())

        self.auto_update_check.setChecked(bool(settings.get("auto_check_updates")))
        self.update_tor_check.setChecked(bool(settings.get("update_via_tor")))
        self.prerelease_check.setChecked(bool(settings.get("update_prerelease")))

        # Reflect what the OS actually has registered, not just our stored flag.
        self.autostart_check.setChecked(get_autostart() or bool(settings.get("start_with_system")))

        self.dlp_edit.setPlainText(self._dlp_rules_text())

        self._update_tor_controls()
        self._update_preview()
        self._update_peer_status()

    def _collect_settings(self) -> dict:
        return {
            "save_dir": self.dest_picker.text(),
            "share_dir": self.share_picker.text(),
            "peers": [
                line.strip() for line in self.peers_edit.toPlainText().splitlines() if line.strip()
            ],
            "team_folder": self.team_edit.text().strip(),
            "only_setup_files": self.only_setups_check.isChecked(),
            "sync_mode": self.sync_mode_combo.currentData(),
            "tor_mode": self.tor_mode_combo.currentData(),
            "tor_path": self.tor_path_picker.text(),
            "socks_port": self.socks_port_spin.value(),
            "control_port": self.control_port_spin.value(),
            "download_limit_bps": self.dl_limit_spin.value() * 1024,
            "upload_limit_bps": self.ul_limit_spin.value() * 1024,
            "max_file_size": self.max_size_spin.value() * 1024 * 1024,
            "sync_interval_seconds": self.interval_spin.value(),
            "av_enabled": self.av_enabled_check.isChecked(),
            "av_block_when_unavailable": self.av_block_check.isChecked(),
            "require_list_token": self.require_token_check.isChecked(),
            "list_access_token": self.access_token_edit.text().strip(),
            "auto_check_updates": self.auto_update_check.isChecked(),
            "update_via_tor": self.update_tor_check.isChecked(),
            "update_prerelease": self.prerelease_check.isChecked(),
            "start_with_system": self.autostart_check.isChecked(),
        }

    def _persist(self) -> None:
        """Push the current UI state into settings and save it."""
        self.settings.update(self._collect_settings())
        if not self.settings.save():
            self.append_log("WARNING: settings could not be written to disk")

        self.controller.state.share_dir = str(self.settings.get("share_dir") or "")
        self.controller.state.refresh_upload_limit()

    def _save_settings_from_ui(self) -> None:
        self._persist()
        self.controller.apply_autostart()
        # normalise() may have corrected values; show the corrected ones back.
        self._load_settings_into_ui()
        self.append_log("Settings saved")
        QMessageBox.information(self, "Settings", "Settings saved.")

    @staticmethod
    def _select_by_data(combo: QComboBox, value) -> None:
        index = combo.findData(value)
        combo.setCurrentIndex(index if index >= 0 else 0)

    # ------------------------------------------------------------------
    # Sync
    # ------------------------------------------------------------------

    def _toggle_sync(self) -> None:
        if self.controller.syncing:
            self.btn_sync.setEnabled(False)
            self._run_task(
                self.controller.stop_sync,
                on_success=lambda _result: self._after_sync_stopped(),
                on_error=self._show_error,
            )
            return

        self._persist()
        self.btn_sync.setEnabled(False)
        self.banner.set_state("busy", "Starting Tor and sync…")

        self._run_task(
            self.controller.start_sync,
            on_success=lambda _result: self._after_sync_started(),
            on_error=self._on_sync_failed,
        )

    def _after_sync_started(self) -> None:
        self.btn_sync.setEnabled(True)
        self.btn_sync.setText("STOP SYNC")
        self._refresh_banner()

    def _after_sync_stopped(self) -> None:
        self.btn_sync.setEnabled(True)
        self.btn_sync.setText("START SYNC")
        self.progress.setValue(0)
        self._refresh_banner()

    def _on_sync_failed(self, message: str) -> None:
        self.btn_sync.setEnabled(True)
        self.btn_sync.setText("START SYNC")
        self._show_error(message)

    # ------------------------------------------------------------------
    # Share
    # ------------------------------------------------------------------

    def _toggle_share(self) -> None:
        if self.controller.sharing:
            self.btn_share.setEnabled(False)
            self._run_task(
                self.controller.stop_sharing,
                on_success=lambda _result: self._after_share_stopped(),
                on_error=self._show_error,
            )
            return

        self._persist()
        self.btn_share.setEnabled(False)
        self.banner.set_state("busy", "Starting Tor and publishing the hidden service…")

        self._run_task(
            self.controller.start_sharing,
            on_success=self._after_share_started,
            on_error=self._on_share_failed,
        )

    def _after_share_started(self, onion: object) -> None:
        self.btn_share.setEnabled(True)
        self.btn_share.setText("STOP SHARING")
        if isinstance(onion, str) and onion:
            self.onion_edit.setText(onion)
        self._refresh_banner()

    def _after_share_stopped(self) -> None:
        self.btn_share.setEnabled(True)
        self.btn_share.setText("START SHARING")
        self.onion_edit.clear()
        self._refresh_banner()

    def _on_share_failed(self, message: str) -> None:
        self.btn_share.setEnabled(True)
        self.btn_share.setText("START SHARING")
        self._show_error(message)

    def _generate_one_time_token(self) -> None:
        if not self.controller.state.share_dir:
            QMessageBox.warning(self, "No folder", "Select a folder to share first.")
            return

        token = self.controller.state.issue_one_time_token(
            self.token_ttl_spin.value() * 60, note="generated from the UI"
        )
        self.onetime_token_edit.setText(token.token)
        self.append_log(f"Issued a one-time token valid for {self.token_ttl_spin.value()} minutes")

    def _generate_access_token(self) -> None:
        from ..security import new_token

        self.access_token_edit.setText(new_token(18))
        self.require_token_check.setChecked(True)

    def _save_dlp_rules(self) -> None:
        text = self.dlp_edit.toPlainText()
        if save_dlp_rules(text):
            self.controller.state.set_dlp_rules(parse_dlp_rules(text))
            self.append_log("Privacy rules saved")
            QMessageBox.information(self, "Rules", "Privacy rules saved.")
        else:
            self._show_error("Could not write the rules file.")

    def _dlp_rules_text(self) -> str:
        try:
            if self.paths.dlp_rules.exists():
                return self.paths.dlp_rules.read_text(encoding="utf-8")
        except OSError:
            pass
        return ""

    def _burn_identity(self) -> None:
        confirm = QMessageBox.question(
            self,
            "Reset identity",
            "This permanently changes your .onion address.\n"
            "Your team will have to be given the new address.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.controller.stop_sharing()
        self.controller.tor.burn_identity()
        self.onion_edit.clear()
        self.btn_share.setText("START SHARING")
        self.append_log("Onion identity reset — a new address is created on the next start")
        QMessageBox.information(
            self, "Identity reset", "A new .onion address will be created next time you share."
        )

    # ------------------------------------------------------------------
    # Updates
    # ------------------------------------------------------------------

    def _make_updater(self) -> Updater:
        proxies = None
        if self.settings.get("update_via_tor") and self.controller.socks_port:
            proxies = socks_proxies(self.controller.socks_port)
        return Updater(
            proxies=proxies,
            allow_prerelease=bool(self.settings.get("update_prerelease")),
        )

    def _check_updates(self, *, silent: bool) -> None:
        if not silent:
            self.btn_check_updates.setEnabled(False)
            self.append_log("Checking for updates…")

        def on_result(info: Optional[UpdateInfo], error: Optional[str]) -> None:
            # Hop back to the GUI thread before touching widgets.
            QTimer.singleShot(0, lambda: self._on_update_result(info, error, silent))

        check_in_background(self._make_updater(), on_result)

    def _on_update_result(
        self, info: Optional[UpdateInfo], error: Optional[str], silent: bool
    ) -> None:
        self.btn_check_updates.setEnabled(True)

        if error:
            self.append_log(f"Update check failed: {error}")
            if not silent:
                QMessageBox.warning(self, "Update check", error)
            return

        if info is None:
            self.append_log(f"You are running the latest version ({__version__})")
            if not silent:
                QMessageBox.information(
                    self, "Up to date", f"{DISPLAY_NAME} {__version__} is the latest version."
                )
            return

        self._pending_update = info
        self.append_log(f"Update available: {info.version}")
        self.update_banner.setText(
            f"<b>Version {info.version} is available.</b> "
            f'<a href="{info.html_url}" style="color:#9ecbff;">Release notes</a>'
        )
        self.update_banner.show()

        if info.can_auto_install:
            self._offer_install(info)
        elif not silent:
            QMessageBox.information(
                self,
                "Update available",
                f"Version {info.version} is available.\n\n"
                f"Download it from:\n{info.html_url}",
            )

    def _offer_install(self, info: UpdateInfo) -> None:
        confirm = QMessageBox.question(
            self,
            "Update available",
            f"Version {info.version} is available (you have {__version__}).\n\n"
            "Download and install it now? The app will close while it updates.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        updater = self._make_updater()
        self.banner.set_state("busy", "Downloading update…")

        def download() -> str:
            path = updater.download(info, progress=self.bridge.progress.emit)
            return str(path)

        self._run_task(download, on_success=self._install_update, on_error=self._on_update_failed)

    def _install_update(self, installer_path: object) -> None:
        try:
            Updater.launch_installer(str(installer_path))
        except UpdateError as exc:
            self._on_update_failed(str(exc))
            return

        self.append_log("Installer started — closing the app so it can be replaced")
        self.controller.shutdown()
        QApplication.quit()

    def _on_update_failed(self, message: str) -> None:
        self._refresh_banner()
        self.append_log(f"Update failed: {message}")
        QMessageBox.warning(self, "Update failed", message)

    # ------------------------------------------------------------------
    # Feedback helpers
    # ------------------------------------------------------------------

    def append_log(self, message: str) -> None:
        import time

        self.log_view.append(f"[{time.strftime('%H:%M:%S')}] {message}")

    def _on_progress(self, percent: int, message: str) -> None:
        self.progress.setValue(max(0, min(100, int(percent))))
        self.progress.setFormat(f"{message} — %p%")

    def _on_security_alert(self, message: str) -> None:
        self.append_log(f"SECURITY: {message}")
        QMessageBox.critical(self, "Security alert", message)

    def _on_file_served(self, name: str, size: int) -> None:
        self._served_count += 1
        self.served_label.setText(f"Files served: {self._served_count}")

    def _refresh_banner(self) -> None:
        sharing = self.controller.sharing
        syncing = self.controller.syncing

        if sharing and syncing:
            self.banner.set_state("ok", "Sharing and syncing over Tor")
        elif sharing:
            self.banner.set_state("ok", f"Sharing at {self.controller.onion_address or 'onion'}")
        elif syncing:
            self.banner.set_state("ok", "Syncing from peers over Tor")
        elif self.controller.tor_running:
            self.banner.set_state("idle", "Tor running — nothing active")
        else:
            self.banner.set_state("idle", "Idle")

    def _update_tor_controls(self) -> None:
        external = self.tor_mode_combo.currentData() == "external"
        self.tor_path_picker.setEnabled(external)

        bundled = find_bundled_tor()
        system = find_system_tor()
        parts = []
        if bundled:
            parts.append(f"bundled: {bundled}")
        if system:
            parts.append(f"system: {system}")
        self.tor_detect_label.setText("; ".join(parts) if parts else "no Tor executable found")

    def _update_preview(self) -> None:
        mode = self.sync_mode_combo.currentData()
        team = self.team_edit.text().strip() or "Team_Setups"
        if mode == "smart":
            preview = f"…/setups/<b>ferrari296gt3</b>/{team}/qualy.sto"
        elif mode == "mirror":
            preview = f"…/setups/{team}/ferrari296gt3/qualy.sto"
        else:
            preview = "…/setups/ferrari296gt3/qualy.sto"
        self.preview_label.setText(preview)

    def _update_peer_status(self) -> None:
        lines = [line.strip() for line in self.peers_edit.toPlainText().splitlines() if line.strip()]
        if not lines:
            self.peers_status.setText("No peers configured")
            return

        valid = sum(1 for line in lines if normalise_peer_url(line))
        invalid = len(lines) - valid
        if invalid:
            self.peers_status.setText(
                f"{valid} valid peer(s); {invalid} entry(ies) are not .onion addresses and will be ignored"
            )
        else:
            self.peers_status.setText(f"{valid} valid peer(s)")

    def _copy(self, text: str, message: str) -> None:
        if not text:
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
            self.append_log(message)

    def _open_folder(self, path: str, label: str) -> None:
        if not path or not open_path(path):
            QMessageBox.information(
                self, "Folder", f"The {label} folder is not set or does not exist yet."
            )

    def _show_error(self, message: str) -> None:
        self._refresh_banner()
        self.append_log(f"ERROR: {message}")
        QMessageBox.critical(self, DISPLAY_NAME, message)

    def _run_task(self, func, *, on_success=None, on_error=None) -> BackgroundTask:
        """Run ``func`` in a worker thread, keeping a reference until it ends."""
        task = BackgroundTask(func, parent=self)

        if on_success is not None:
            task.succeeded.connect(on_success)
        if on_error is not None:
            task.failed.connect(on_error)

        task.finished.connect(lambda: self._tasks.remove(task) if task in self._tasks else None)
        self._tasks.append(task)
        task.start()
        return task

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        try:
            self._persist()
        except Exception:
            logger.exception("Could not save settings on exit")

        try:
            self.controller.shutdown()
        except Exception:
            logger.exception("Error during shutdown")

        for task in list(self._tasks):
            task.wait(2000)

        event.accept()


def run(argv: Optional[List[str]] = None) -> int:
    """Create the application and run the Qt event loop."""
    configure_logging()

    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(DISPLAY_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(DISPLAY_NAME)

    window = MainWindow()
    window.show()

    return app.exec()
