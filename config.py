from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_PATH = Path("config.json")


@dataclass
class Thresholds:
    """Detection thresholds that govern alerting behavior."""

    risk: float = 0.7
    write_frequency: int = 8
    rapid_modifications: int = 5
    rename_write_window: float = 10.0  # seconds


DEFAULT_THRESHOLDS = Thresholds()
DEFAULT_MONITORED_PATHS = [str(Path.home())]
DEFAULT_WHITELIST: List[str] = []
DEFAULT_POLLING_INTERVAL = 1.5


@dataclass
class Config:
    """Runtime configuration for Kavach."""

    monitored_paths: List[str] = field(default_factory=lambda: DEFAULT_MONITORED_PATHS.copy())
    whitelist: List[str] = field(default_factory=lambda: DEFAULT_WHITELIST.copy())
    polling_interval: float = DEFAULT_POLLING_INTERVAL
    thresholds: Thresholds = field(default_factory=Thresholds)


def _parse_thresholds(data: Dict[str, Any]) -> Thresholds:
    defaults = DEFAULT_THRESHOLDS
    return Thresholds(
        risk=float(data.get("risk", defaults.risk)),
        write_frequency=int(data.get("write_frequency", defaults.write_frequency)),
        rapid_modifications=int(
            data.get("rapid_modifications", defaults.rapid_modifications)
        ),
        rename_write_window=float(
            data.get("rename_write_window", defaults.rename_write_window)
        ),
    )


def load_config(path: Optional[str | Path] = None) -> Config:
    """Load configuration from JSON file, or return defaults."""

    target = Path(path) if path else DEFAULT_CONFIG_PATH
    if not target.exists():
        return Config()

    with target.open("r", encoding="utf-8") as fp:
        raw = json.load(fp)

    thresholds = raw.get("thresholds", {})
    monitored_paths = raw.get("monitored_paths")
    whitelist = raw.get("whitelist")

    return Config(
        monitored_paths=list(monitored_paths)
        if monitored_paths
        else DEFAULT_MONITORED_PATHS.copy(),
        whitelist=list(whitelist) if whitelist else DEFAULT_WHITELIST.copy(),
        polling_interval=float(raw.get("polling_interval", DEFAULT_POLLING_INTERVAL)),
        thresholds=_parse_thresholds(thresholds),
    )


def save_config(config: Config, path: Optional[str | Path] = None) -> None:
    """Persist configuration to disk."""

    target = Path(path) if path else DEFAULT_CONFIG_PATH
    data = asdict(config)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)

