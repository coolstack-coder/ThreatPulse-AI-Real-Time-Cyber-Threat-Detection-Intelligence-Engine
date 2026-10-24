"""Engine configuration.

Defaults live here. A YAML file (``config/threatpulse.yaml``) can override any section, and a
few operational settings can also come from environment variables, 12-factor style.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class FlowConfig:
    tcp_idle_timeout: float = 30.0
    udp_idle_timeout: float = 15.0
    active_timeout: float = 60.0
    max_flows: int = 200_000
    sweep_interval: float = 1.0


@dataclass
class ScanConfig:
    window: float = 10.0
    vertical_ports: int = 25  # distinct ports on a single host
    horizontal_targets: int = 30  # distinct (host, port) pairs


@dataclass
class FloodConfig:
    window: float = 5.0
    min_syn: int = 400
    max_synack_ratio: float = 0.3


@dataclass
class BruteForceConfig:
    window: float = 60.0
    min_attempts: int = 12
    auth_ports: list[int] = field(default_factory=lambda: [21, 22, 23, 3389, 5900, 1433, 3306])
    max_attempt_bytes: int = 8000
    success_min_duration: float = 8.0
    success_min_bytes: int = 20_000


@dataclass
class LateralConfig:
    window: float = 120.0
    min_targets: int = 5
    admin_ports: list[int] = field(default_factory=lambda: [22, 135, 139, 445, 3389, 5985, 5986])


@dataclass
class ExfilConfig:
    window: float = 300.0
    min_bytes: int = 20_000_000
    min_ratio: float = 8.0
    max_rarity: int = 2


@dataclass
class BeaconConfig:
    min_events: int = 8
    max_cv: float = 0.25
    min_interval: float = 1.0
    max_rarity: int = 2
    history: int = 24


@dataclass
class DnsConfig:
    window: float = 60.0
    min_unique: int = 25
    min_entropy: float = 3.4
    long_label: int = 40
    min_long: int = 8


@dataclass
class AnomalyConfig:
    enabled: bool = True
    trees: int = 25
    depth: int = 10
    window: int = 256
    warmup_flows: int = 1500
    quantile: float = 0.998
    cooldown: float = 60.0


@dataclass
class VolumeConfig:
    bucket: float = 10.0
    alpha: float = 0.1
    z_threshold: float = 6.0
    min_bytes: int = 10_000_000
    warmup_buckets: int = 6


@dataclass
class CorrelationConfig:
    window: float = 1800.0
    min_new_incident_severity: int = 2  # MEDIUM
    llm_min_severity: int = 3  # HIGH


@dataclass
class DetectionConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    flood: FloodConfig = field(default_factory=FloodConfig)
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    lateral: LateralConfig = field(default_factory=LateralConfig)
    exfil: ExfilConfig = field(default_factory=ExfilConfig)
    beacon: BeaconConfig = field(default_factory=BeaconConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    volume: VolumeConfig = field(default_factory=VolumeConfig)
    alert_cooldown: float = 60.0


@dataclass
class LLMConfig:
    api_key: str = ""
    base_url: str = "https://api.x.ai/v1"
    model: str = "grok-3-mini"
    timeout: float = 20.0
    enabled: bool = True


@dataclass
class Settings:
    flow: FlowConfig = field(default_factory=FlowConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    db_path: str = str(ROOT / "data" / "threatpulse.db")
    ioc_path: str = str(ROOT / "config" / "intel" / "ioc.txt")
    assets_path: str = str(ROOT / "config" / "assets.yaml")
    queue_size: int = 50_000


def _merge(obj: Any, data: dict[str, Any]) -> Any:
    for f in fields(obj):
        if f.name not in data:
            continue
        cur = getattr(obj, f.name)
        val = data[f.name]
        if is_dataclass(cur) and isinstance(val, dict):
            _merge(cur, val)
        else:
            setattr(obj, f.name, val)
    return obj


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    settings = Settings()
    path = path or os.getenv("THREATPULSE_CONFIG") or ROOT / "config" / "threatpulse.yaml"
    p = Path(path)
    if p.exists():
        _merge(settings, yaml.safe_load(p.read_text()) or {})

    # Environment variables override the YAML.
    settings.llm.api_key = (
        os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY") or settings.llm.api_key
    )
    settings.llm.base_url = os.getenv("THREATPULSE_LLM_BASE_URL", settings.llm.base_url)
    settings.llm.model = os.getenv("THREATPULSE_LLM_MODEL", settings.llm.model)
    settings.db_path = os.getenv("THREATPULSE_DB", settings.db_path)
    return settings
