from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDoubleSpinBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from config import Config, load_config, save_config
from monitor_worker import MonitorWorker


class MainWindow(QMainWindow):
    """Primary GUI for the Kavach ransomware detection dashboard."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Kavach - Ransomware Detection Dashboard")
        self.resize(900, 600)

        self.config: Config = load_config()
        self.worker: Optional[MonitorWorker] = None

        self._build_ui()
        self._connect_actions()
        self._update_controls()

    # UI setup ---------------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)

        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")

        self.threshold_spin = QDoubleSpinBox()
        self.threshold_spin.setRange(0.1, 1.0)
        self.threshold_spin.setSingleStep(0.05)
        self.threshold_spin.setValue(self.config.thresholds.risk)
        self.threshold_spin.setSuffix(" risk")

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Risk threshold:"))
        controls_layout.addWidget(self.threshold_spin)
        controls_layout.addStretch()
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)

        self.status_label = QLabel("Idle")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.log_table = QTableWidget(0, 5)
        self.log_table.setHorizontalHeaderLabels(
            ["Time", "Path", "Operation", "Risk", "Details"]
        )
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(0, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, header.ResizeMode.Stretch)
        header.setSectionResizeMode(2, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, header.ResizeMode.Stretch)

        layout = QVBoxLayout()
        layout.addLayout(controls_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.log_table)

        central.setLayout(layout)

    def _connect_actions(self) -> None:
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.threshold_spin.valueChanged.connect(self._threshold_changed)

    def _update_controls(self) -> None:
        running = self.worker is not None and self.worker.isRunning()
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)

    # Worker lifecycle -------------------------------------------------

    def start_monitoring(self) -> None:
        if self.worker and self.worker.isRunning():
            return

        self.status_label.setText("Starting monitor...")
        self.config.thresholds.risk = self.threshold_spin.value()
        save_config(self.config)

        self.worker = MonitorWorker(self.config)
        self.worker.alertSignal.connect(self._handle_alert)
        self.worker.logSignal.connect(self._handle_log)
        self.worker.statusSignal.connect(self._update_status)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()
        self._update_controls()

    def stop_monitoring(self) -> None:
        if not self.worker:
            return
        self.status_label.setText("Stopping monitor...")
        self.worker.stop()

    def _threshold_changed(self, value: float) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.update_risk_threshold(value)

    def _worker_finished(self) -> None:
        self.worker = None
        self._update_controls()
        self.status_label.setText("Monitor stopped")

    # Signal handlers --------------------------------------------------

    def _handle_alert(self, payload: Dict) -> None:
        risk = payload.get("risk", 0.0)
        message = payload.get("message", "Suspicious behavior detected")
        QMessageBox.warning(
            self,
            "Ransomware Alert",
            f"{message}\nRisk score: {risk:.2f}",
        )

    def _handle_log(self, payload: Dict) -> None:
        timestamp = datetime.fromtimestamp(payload.get("timestamp", 0.0))
        path = payload.get("path", "unknown")
        operation = payload.get("operation", "n/a")
        risk = payload.get("risk", 0.0)
        features = payload.get("features", {})
        details = ", ".join(
            f"{key}={value:.2f}" if isinstance(value, float) else f"{key}={value}"
            for key, value in features.items()
        )

        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        self.log_table.setItem(row, 0, QTableWidgetItem(timestamp.strftime("%H:%M:%S")))
        self.log_table.setItem(row, 1, QTableWidgetItem(path))
        self.log_table.setItem(row, 2, QTableWidgetItem(operation))
        self.log_table.setItem(row, 3, QTableWidgetItem(f"{risk:.2f}"))
        self.log_table.setItem(row, 4, QTableWidgetItem(details))
        self.log_table.scrollToBottom()

    def _update_status(self, message: str) -> None:
        self.status_label.setText(message)

    # Qt overrides -----------------------------------------------------

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self.worker and self.worker.isRunning():
            self.worker.stop()
        super().closeEvent(event)


