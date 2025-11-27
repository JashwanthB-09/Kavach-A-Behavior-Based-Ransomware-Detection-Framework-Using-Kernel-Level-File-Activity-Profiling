from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from config import Config
from detector import (
    FileEvent,
    compute_risk_score,
    estimate_entropy,
    extract_features,
    is_ransomware_like,
)


@dataclass
class FileState:
    """Track last-known properties of a file."""

    size: int
    mtime: float
    entropy: Optional[float]


class MonitorWorker(QThread):
    """Background worker that polls directories for ransomware-like activity."""

    alertSignal = pyqtSignal(dict)
    logSignal = pyqtSignal(dict)
    statusSignal = pyqtSignal(str)

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config
        self._stop_event = threading.Event()
        self._snapshot: Dict[Path, FileState] = {}
        self._history: Deque[FileEvent] = deque(maxlen=512)

    def run(self) -> None:
        self.statusSignal.emit("Initializing monitor...")
        self._initialize_snapshot()
        self.statusSignal.emit("Monitoring started")
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:  # pragma: no cover - defensive path
                self.statusSignal.emit(f"Monitoring error: {exc}")
            self._stop_event.wait(self.config.polling_interval)

        self.statusSignal.emit("Monitoring stopped")

    def stop(self) -> None:
        self._stop_event.set()
        self.wait(1000)

    def update_risk_threshold(self, value: float) -> None:
        self.config.thresholds.risk = value

    # Internal helpers -------------------------------------------------

    def _initialize_snapshot(self) -> None:
        for path in self._iter_monitored_files():
            self._snapshot[path] = self._read_state(path)

    def _poll_once(self) -> None:
        current_paths = set()
        for file_path in self._iter_monitored_files():
            current_paths.add(file_path)
            previous = self._snapshot.get(file_path)
            current_state = self._read_state(file_path)
            if self._has_changed(previous, current_state):
                self._handle_event(file_path, previous, current_state)
            self._snapshot[file_path] = current_state

        # Remove deleted files from snapshot
        removed = set(self._snapshot) - current_paths
        for stale_path in removed:
            del self._snapshot[stale_path]

    def _iter_monitored_files(self) -> Iterable[Path]:
        for root in self.config.monitored_paths:
            path = Path(root).expanduser()
            if not path.exists():
                self.statusSignal.emit(f"Path not found: {path}")
                continue
            if path.is_file():
                if not self._is_whitelisted(path):
                    yield path
                continue
            for dirpath, _, filenames in os.walk(path):
                dir_path = Path(dirpath)
                if self._is_whitelisted(dir_path):
                    continue
                for name in filenames:
                    candidate = dir_path / name
                    if self._is_whitelisted(candidate):
                        continue
                    if candidate.is_file():
                        yield candidate

    def _is_whitelisted(self, path: Path) -> bool:
        normalized = str(path).lower()
        for entry in self.config.whitelist:
            if normalized.startswith(entry.lower()):
                return True
        return False

    def _read_state(self, path: Path) -> FileState:
        try:
            stat = path.stat()
        except (FileNotFoundError, PermissionError):
            return FileState(size=0, mtime=0.0, entropy=None)

        entropy = estimate_entropy(path)
        return FileState(size=stat.st_size, mtime=stat.st_mtime, entropy=entropy)

    @staticmethod
    def _has_changed(old: Optional[FileState], new: FileState) -> bool:
        if old is None:
            return True
        return old.mtime != new.mtime or old.size != new.size

    def _handle_event(
        self, path: Path, previous: Optional[FileState], current: FileState
    ) -> None:
        timestamp = time.time()
        operation = "write" if previous else "create"
        event = FileEvent(
            path=path,
            process_name="unknown",
            operation=operation,
            timestamp=timestamp,
            size=current.size,
            entropy=current.entropy,
        )
        self._history.append(event)
        features = extract_features(
            event, self._history, window=self.config.thresholds.rename_write_window
        )
        risk = compute_risk_score(features, self.config.thresholds)
        suspicious = is_ransomware_like(features, self.config.thresholds)

        log_payload = {
            "path": str(path),
            "operation": operation,
            "timestamp": timestamp,
            "risk": risk,
            "features": features,
        }
        self.logSignal.emit(log_payload)

        if suspicious:
            alert_payload = {
                "path": str(path),
                "risk": risk,
                "timestamp": timestamp,
                "message": f"Suspicious activity detected on {path}",
            }
            self.alertSignal.emit(alert_payload)

