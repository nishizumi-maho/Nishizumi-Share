"""Small reusable Qt helpers."""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QWidget,
)


class SignalBridge(QObject):
    """Thread-safe funnel for callbacks coming from worker threads.

    Qt queues signals emitted from non-GUI threads, so background code can call
    ``bridge.log.emit(...)`` directly without touching widgets.
    """

    log = pyqtSignal(str)
    progress = pyqtSignal(int, str)
    alert = pyqtSignal(str)
    file_served = pyqtSignal(str, int)


class BackgroundTask(QThread):
    """Runs one callable off the GUI thread and reports the outcome."""

    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, func: Callable, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._func = func

    def run(self) -> None:
        try:
            result = self._func()
        except Exception as exc:
            self.failed.emit(str(exc) or exc.__class__.__name__)
            return
        self.succeeded.emit(result)


class PathPicker(QWidget):
    """A read-only line edit plus a Browse button."""

    def __init__(
        self,
        caption: str,
        *,
        directory: bool = True,
        file_filter: str = "All files (*)",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._caption = caption
        self._directory = directory
        self._file_filter = file_filter

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.edit = QLineEdit()
        self.edit.setPlaceholderText(caption)
        self.button = QPushButton("Browse…")
        self.button.clicked.connect(self._browse)

        layout.addWidget(self.edit, stretch=1)
        layout.addWidget(self.button)

    def _browse(self) -> None:
        if self._directory:
            chosen = QFileDialog.getExistingDirectory(self, self._caption, self.edit.text())
        else:
            chosen, _ = QFileDialog.getOpenFileName(
                self, self._caption, self.edit.text(), self._file_filter
            )
        if chosen:
            self.edit.setText(chosen)

    def text(self) -> str:
        return self.edit.text().strip()

    def setText(self, value: str) -> None:
        self.edit.setText(value or "")


class StatusBanner(QLabel):
    """Coloured status strip shown at the top of the window."""

    _STYLES = {
        "idle": "background:#3a3f44; color:#f0f0f0;",
        "busy": "background:#b8860b; color:#101010;",
        "ok": "background:#1f7a3d; color:#ffffff;",
        "error": "background:#8b1a1a; color:#ffffff;",
    }

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.set_state("idle", "Idle")

    def set_state(self, state: str, message: str) -> None:
        style = self._STYLES.get(state, self._STYLES["idle"])
        self.setText(message)
        self.setStyleSheet(
            f"{style} padding:10px; font-weight:600; border-radius:6px;"
        )
