"""Core data types shared by every stage of the pipeline.

Packets come in, flows are assembled from them, detectors turn packets and flows into
alerts, and the correlator folds alerts into incidents.
"""

from __future__ import annotations

import itertools
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_score(cls, score: float) -> Severity:
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        return cls.LOW


@dataclass(slots=True)
class Packet:
    """A single observed packet (or a coalesced segment, as GRO/TSO captures produce)."""

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str  # "TCP" | "UDP" | "ICMP"
    size: int
    flags: str = ""  # TCP flags, e.g. "S", "SA", "A", "PA", "FA", "R"
    dns_query: str | None = None
    dns_qtype: str | None = None
    # Ground truth from the simulator. Detectors never read these fields; they exist only
    # so the evaluation harness can score the detectors.
    label: str = "benign"
    campaign: str | None = None


_flow_ids = itertools.count(1)


@dataclass(slots=True)
class Flow:
    """A bidirectional flow, oriented from the endpoint that sent the first packet."""

    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    start: float
    last: float
    id: int = field(default_factory=lambda: next(_flow_ids))
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_max: int = 0
    syn: int = 0
    synack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    # Welford running stats for inter-arrival times
    iat_n: int = 0
    iat_mean: float = 0.0
    iat_m2: float = 0.0
    dns_queries: list[str] = field(default_factory=list)
    closed_by: str = ""  # "fin" | "rst" | "idle" | "active" | "flush"
    labels: dict[str, int] = field(default_factory=dict)
    campaigns: set[str] = field(default_factory=set)

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.start)

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def total_pkts(self) -> int:
        return self.fwd_pkts + self.bwd_pkts

    @property
    def iat_std(self) -> float:
        return (self.iat_m2 / (self.iat_n - 1)) ** 0.5 if self.iat_n > 1 else 0.0

    @property
    def truth(self) -> str:
        """Majority ground-truth label (evaluation only)."""
        if not self.labels:
            return "benign"
        return max(self.labels.items(), key=lambda kv: kv[1])[0]

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "proto": self.proto,
            "start": round(self.start, 3),
            "duration": round(self.duration, 3),
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "pkts": self.total_pkts,
            "closed_by": self.closed_by,
        }


@dataclass
class Alert:
    """One detection, produced by a single detector."""

    ts: float
    detector: str
    type: str
    title: str
    severity: Severity
    score: float
    attacker: str | None = None
    victim: str | None = None
    peers: list[str] = field(default_factory=list)
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    tactic: str = ""
    technique: str = ""
    technique_name: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    incident_id: str | None = None
    created_wall: float = field(default_factory=time.time)
    enrichment: dict[str, Any] = field(default_factory=dict)
    # Ground truth (evaluation only)
    truth: str = "benign"
    campaigns: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["campaigns"] = sorted(self.campaigns)
        d["score"] = round(self.score, 1)
        return d


@dataclass
class Incident:
    """A group of alerts that tell one story, ordered along the kill chain."""

    id: str
    first_seen: float
    last_seen: float
    title: str = ""
    status: str = "open"  # open | acknowledged | resolved
    severity: Severity = Severity.LOW
    risk: float = 0.0
    attackers: set[str] = field(default_factory=set)
    victims: set[str] = field(default_factory=set)
    compromised: set[str] = field(default_factory=set)
    tactics: list[str] = field(default_factory=list)
    techniques: dict[str, str] = field(default_factory=dict)
    alert_ids: list[str] = field(default_factory=list)
    alert_types: dict[str, int] = field(default_factory=dict)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    summary_source: str = ""  # "llm" | "template"
    recommendations: list[str] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)
    campaigns: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity.label,
            "risk": round(self.risk, 1),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attackers": sorted(self.attackers),
            "victims": sorted(self.victims),
            "compromised": sorted(self.compromised),
            "tactics": self.tactics,
            "techniques": self.techniques,
            "alert_count": len(self.alert_ids),
            "alert_types": self.alert_types,
            "timeline": self.timeline[-60:],
            "summary": self.summary,
            "summary_source": self.summary_source,
            "recommendations": self.recommendations,
            "enrichment": self.enrichment,
            "campaigns": sorted(self.campaigns),
        }
