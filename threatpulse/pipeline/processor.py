"""The synchronous detection core: packet in, alerts out.

The processor is deliberately free of asyncio and I/O, so the same code runs the live
engine, PCAP replays, the evaluation harness, benchmarks and unit tests.
"""

from __future__ import annotations

from collections.abc import Callable

from ..config import Settings
from ..detection.anomaly import FlowAnomalyDetector, VolumeAnomalyDetector
from ..detection.base import Detector, TrafficContext
from ..detection.behavior import BeaconDetector, DnsTunnelDetector
from ..detection.intel import IocDetector, IocFeed
from ..detection.rules import (
    BruteForceDetector,
    ExfiltrationDetector,
    LateralMovementDetector,
    PortScanDetector,
    SynFloodDetector,
)
from ..models import Alert, Flow, Packet
from .flows import FlowAssembler


def _overrides(d: Detector, hook: str) -> bool:
    return getattr(type(d), hook) is not getattr(Detector, hook)


class Processor:
    def __init__(self, settings: Settings, ioc: IocFeed | None = None, admin_hosts: set[str] | None = None):
        self.settings = settings
        det = settings.detection
        self.flows = FlowAssembler(settings.flow)
        self.ctx = TrafficContext()
        self.ioc = ioc or IocFeed()
        self.anomaly = FlowAnomalyDetector(det, self.ctx)
        self.detectors: list[Detector] = [
            PortScanDetector(det, self.ctx),
            SynFloodDetector(det, self.ctx),
            BruteForceDetector(det, self.ctx),
            LateralMovementDetector(det, self.ctx, admin_hosts=admin_hosts),
            ExfiltrationDetector(det, self.ctx),
            BeaconDetector(det, self.ctx),
            DnsTunnelDetector(det, self.ctx),
            IocDetector(det, self.ctx, self.ioc),
            self.anomaly,
            VolumeAnomalyDetector(det, self.ctx),
        ]
        self._pkt = [d for d in self.detectors if _overrides(d, "on_packet")]
        self._flow = [d for d in self.detectors if _overrides(d, "on_flow")]
        self._tick = [d for d in self.detectors if _overrides(d, "on_tick")]
        self._last_tick: float | None = None
        self.flow_listeners: list[Callable[[Flow], None]] = []
        self.packets = 0
        self.bytes = 0
        self.flows_done = 0
        self.alerts = 0

    def process(self, p: Packet) -> list[Alert]:
        self.packets += 1
        self.bytes += p.size
        out: list[Alert] = []
        for d in self._pkt:
            res = d.on_packet(p)
            if res:
                out.extend(res)
        for flow in self.flows.process(p):
            self._on_flow(flow, out)
        if self._last_tick is None:
            self._last_tick = p.ts
        elif p.ts - self._last_tick >= 1.0:
            out.extend(self.tick(p.ts))
        self.alerts += len(out)
        return out

    def _on_flow(self, flow: Flow, out: list[Alert]) -> None:
        self.flows_done += 1
        self.ctx.observe(flow)
        for d in self._flow:
            res = d.on_flow(flow)
            if res:
                out.extend(res)
        for cb in self.flow_listeners:
            cb(flow)

    def tick(self, now: float) -> list[Alert]:
        self._last_tick = now
        out: list[Alert] = []
        for flow in self.flows.sweep(now):
            self._on_flow(flow, out)
        for d in self._tick:
            res = d.on_tick(now)
            if res:
                out.extend(res)
        return out

    def flush(self) -> list[Alert]:
        out: list[Alert] = []
        for flow in self.flows.flush():
            self._on_flow(flow, out)
        self.alerts += len(out)
        return out

    def detector_stats(self) -> dict[str, int]:
        return {d.name: d.fired for d in self.detectors}
