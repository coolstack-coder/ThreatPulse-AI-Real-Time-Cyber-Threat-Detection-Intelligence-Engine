"""Detector interface plus the shared traffic context detectors read from."""

from __future__ import annotations

from collections import OrderedDict, deque
from typing import Any

from ..config import DetectionConfig
from ..correlation.mitre import technique_for
from ..models import Alert, Flow, Packet, Severity
from ..netutil import is_internal


class TrafficContext:
    """State that several detectors share.

    For now this is destination rarity: how many distinct internal hosts have talked to an
    external address recently. Nearly every legitimate SaaS endpoint is contacted by many
    hosts, while C2 and exfiltration endpoints are usually contacted by one, so rarity is a
    strong way to suppress false positives.
    """

    def __init__(self, window: float = 3600.0, max_dsts: int = 100_000):
        self.window = window
        self.max_dsts = max_dsts
        self._seen: OrderedDict[str, dict[str, float]] = OrderedDict()

    def observe(self, flow: Flow) -> None:
        if is_internal(flow.src) and not is_internal(flow.dst):
            peers = self._seen.get(flow.dst)
            if peers is None:
                peers = self._seen[flow.dst] = {}
                if len(self._seen) > self.max_dsts:
                    self._seen.popitem(last=False)
            else:
                self._seen.move_to_end(flow.dst)
            peers[flow.src] = flow.last
            if len(peers) > 64:  # cap memory for very popular destinations
                oldest = min(peers, key=peers.__getitem__)
                del peers[oldest]

    def rarity(self, dst: str, now: float) -> int:
        """Number of distinct internal hosts that contacted ``dst`` within the window."""
        peers = self._seen.get(dst)
        if not peers:
            return 0
        return sum(1 for ts in peers.values() if now - ts <= self.window)


class Detector:
    name = "base"

    def __init__(self, cfg: DetectionConfig, ctx: TrafficContext):
        self.cfg = cfg
        self.ctx = ctx
        self._cooldowns: dict[Any, float] = {}
        self.fired = 0

    # Hooks. A detector overrides the ones it needs.
    def on_packet(self, p: Packet) -> list[Alert] | None:
        return None

    def on_flow(self, f: Flow) -> list[Alert] | None:
        return None

    def on_tick(self, now: float) -> list[Alert] | None:
        return None

    def cooling(self, key: Any, ts: float, period: float | None = None) -> bool:
        """True while ``key`` is still in cooldown. Unlike ``ready``, this records nothing."""
        period = self.cfg.alert_cooldown if period is None else period
        last = self._cooldowns.get(key)
        return last is not None and ts - last < period

    def ready(self, key: Any, ts: float, period: float | None = None) -> bool:
        """Cooldown gate: True at most once per ``period`` for each key."""
        period = self.cfg.alert_cooldown if period is None else period
        last = self._cooldowns.get(key)
        if last is not None and ts - last < period:
            return False
        self._cooldowns[key] = ts
        if len(self._cooldowns) > 50_000:
            cutoff = ts - period
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v >= cutoff}
        return True

    def alert(
        self,
        type: str,
        ts: float,
        title: str,
        score: float,
        *,
        attacker: str | None = None,
        victim: str | None = None,
        peers: list[str] | None = None,
        description: str = "",
        evidence: dict[str, Any] | None = None,
        campaigns: set[str] | None = None,
    ) -> Alert:
        tech = technique_for(type)
        self.fired += 1
        score = max(0.0, min(100.0, score))
        return Alert(
            ts=ts,
            detector=self.name,
            type=type,
            title=title,
            severity=Severity.from_score(score),
            score=score,
            attacker=attacker,
            victim=victim,
            peers=peers or [],
            description=description,
            evidence=evidence or {},
            tactic=tech.tactic,
            technique=tech.id,
            technique_name=tech.name,
            campaigns=set(campaigns or ()),
        )


class WindowedSet:
    """Distinct items seen within a sliding event-time window, with O(1) amortised updates."""

    __slots__ = ("window", "_events", "_last")

    def __init__(self, window: float):
        self.window = window
        self._events: deque[tuple[float, Any]] = deque()
        self._last: dict[Any, float] = {}

    def add(self, ts: float, item: Any) -> None:
        self._events.append((ts, item))
        self._last[item] = ts
        self.expire(ts)

    def expire(self, now: float) -> None:
        cutoff = now - self.window
        ev, last = self._events, self._last
        while ev and ev[0][0] < cutoff:
            ts, item = ev.popleft()
            if last.get(item) == ts:
                del last[item]

    def __len__(self) -> int:
        return len(self._last)

    def items(self):
        return self._last.keys()


class WindowedCounter:
    """Sum of values within a sliding event-time window."""

    __slots__ = ("window", "_events", "total")

    def __init__(self, window: float):
        self.window = window
        self._events: deque[tuple[float, float]] = deque()
        self.total = 0.0

    def add(self, ts: float, value: float = 1.0) -> float:
        self._events.append((ts, value))
        self.total += value
        self.expire(ts)
        return self.total

    def expire(self, now: float) -> None:
        cutoff = now - self.window
        ev = self._events
        while ev and ev[0][0] < cutoff:
            self.total -= ev.popleft()[1]

    def __len__(self) -> int:
        return len(self._events)
