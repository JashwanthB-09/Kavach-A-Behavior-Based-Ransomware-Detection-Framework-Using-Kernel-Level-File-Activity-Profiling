from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from config import Thresholds


@dataclass
class FileEvent:
    """Normalized representation of a file system event."""

    path: Path
    process_name: str
    operation: str
    timestamp: float
    size: int
    entropy: Optional[float] = None


def _shannon_entropy(data: bytes) -> float:
    """Approximate file entropy for ransomware-like detection."""

    if not data:
        return 0.0

    histogram = [0] * 256
    for byte in data:
        histogram[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in histogram:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def estimate_entropy(path: Path, sample_size: int = 64 * 1024) -> Optional[float]:
    """Read a slice of the file and estimate entropy."""

    if not path.is_file():
        return None

    try:
        with path.open("rb") as handle:
            chunk = handle.read(sample_size)
    except (OSError, PermissionError):
        return None

    return _shannon_entropy(chunk)


def extract_features(
    event: FileEvent, history: Iterable[FileEvent], window: float = 10.0
) -> Dict[str, float]:
    """Derive behavior features from the latest event and its history."""

    now = event.timestamp

    recent_events = [e for e in history if now - e.timestamp <= window]
    writes_same_file = [
        e for e in recent_events if e.path == event.path and e.operation == "write"
    ]
    rename_then_write = any(
        e.path == event.path and e.operation == "rename" for e in recent_events
    ) and event.operation == "write"

    features = {
        "write_frequency": float(len(writes_same_file)),
        "rapid_modifications": float(len(recent_events)),
        "rename_write_pattern": 1.0 if rename_then_write else 0.0,
        "size": float(event.size),
        "entropy": event.entropy or 0.0,
        "window": window,
    }
    return features


def compute_risk_score(features: Dict[str, float], thresholds: Thresholds) -> float:
    """Combine features into a normalized risk score."""

    score = 0.0

    if features["write_frequency"] >= thresholds.write_frequency:
        score += 0.35

    if features["rapid_modifications"] >= thresholds.rapid_modifications:
        score += 0.35

    if features["rename_write_pattern"] >= 1.0:
        score += 0.2

    if features["entropy"] >= 6.5:  # heuristic threshold
        score += 0.1

    return min(score, 1.0)


def is_ransomware_like(features: Dict[str, float], thresholds: Thresholds) -> bool:
    """Evaluate whether the behavior warrants an alert."""

    risk = compute_risk_score(features, thresholds)
    return risk >= thresholds.risk

