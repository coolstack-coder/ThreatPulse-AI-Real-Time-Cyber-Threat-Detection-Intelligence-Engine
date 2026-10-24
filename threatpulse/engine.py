"""The async runtime that ties everything together.

    source ──► bounded ingest queue ──► [block list] ──► Processor (flows + detectors)
                                                              │ alerts
                                                              ▼
                       Store ◄── Correlator (incidents) ◄── enrichment (geo, assets)
                                     │                         │
                                     ▼                         ▼
                              LLM narrator             EventBus ──► WebSocket dashboards
                                                                 └► Prometheus metrics

Producer and consumer are separate tasks joined by a bounded queue, so a traffic burst gets
counted as drops (visible in the metrics) instead of growing memory without limit.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import Counter
from typing import Any

from . import __version__
from .bus import EventBus
from .config import Settings
from .correlation.engine import Correlator
from .detection.intel import IocFeed
from .intel.assets import AssetInventory
from .intel.geo import GeoResolver
from .intel.llm import IncidentNarrator
from .models import Alert, Flow, Incident, Packet
from .observability import metrics as m
from .observability.live import LiveStats
from .pipeline.processor import Processor
from .response.blocklist import Blocklist
from .sources.simulator import SCENARIOS, TrafficSimulator
from .storage.store import Store

log = logging.getLogger("threatpulse.engine")


class Engine:
    def __init__(self, settings: Settings, source: str = "sim", *, speed: float = 1.0, seed: int = 42,
                 auto_attack: float = 0.0, pcap: str | None = None, iface: str | None = None,
                 intensity: float = 1.0):
        self.settings = settings
        self.source = source
        self.speed = speed
        self.auto_attack = auto_attack
        self.pcap = pcap
        self.iface = iface

        self.assets = AssetInventory.load(settings.assets_path)
        self.geo = GeoResolver()
        self.ioc = IocFeed.load(settings.ioc_path)
        self.processor = Processor(settings, self.ioc, self.assets.admin_hosts)
        self.correlator = Correlator(settings.correlation, self.assets, self.geo)
        self.store = Store(settings.db_path)
        self.narrator = IncidentNarrator(settings.llm)
        self.blocklist = Blocklist()
        self.bus = EventBus()
        self.stats = LiveStats()
        self.queue: asyncio.Queue[Packet] = asyncio.Queue(maxsize=settings.queue_size)
        self.sim = TrafficSimulator(self.assets, seed=seed, start=time.time(), intensity=intensity) \
            if source == "sim" else None

        self.recent_alerts: list[dict] = []
        self.started = time.time()
        self.running = False
        self._tasks: list[asyncio.Task] = []
        self._dirty_incidents: dict[str, Incident] = {}
        self._last_packet_wall = 0.0
        self._source_done = False
        self._background: set[asyncio.Task] = set()

        self.processor.flow_listeners.append(self._on_flow)
        self.correlator.listeners.append(self._on_incident)

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self.running = True
        self.started = time.time()
        producer = {"sim": self._produce_sim, "pcap": self._produce_pcap, "live": self._produce_live}[self.source]
        self._tasks = [
            asyncio.create_task(producer(), name="producer"),
            asyncio.create_task(self._consume(), name="consumer"),
            asyncio.create_task(self._ticker(), name="ticker"),
        ]
        if self.sim and self.auto_attack > 0:
            self._tasks.append(asyncio.create_task(self._auto_attacks(), name="auto-attack"))
        log.info("ThreatPulse %s started: source=%s llm=%s ioc=%d", __version__, self.source,
                 "on" if self.narrator.enabled else "off", len(self.ioc))

    async def stop(self) -> None:
        self.running = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        await self.narrator.close()
        self.store.close()

    # ------------------------------------------------------------------ sources
    def _enqueue(self, p: Packet) -> None:
        try:
            self.queue.put_nowait(p)
        except asyncio.QueueFull:
            m.DROPPED.labels("queue_full").inc()
            self.stats.on_drop()

    async def _produce_sim(self) -> None:
        assert self.sim is not None
        wall0, sim0 = time.time(), self.sim.now
        while self.running:
            target = sim0 + (time.time() - wall0) * self.speed
            for p in self.sim.advance(target):
                self._enqueue(p)
            await asyncio.sleep(0.05)

    async def _produce_pcap(self) -> None:
        from .sources.capture import read_pcap

        it = read_pcap(self.pcap or "")
        first_ts = wall0 = None
        for p in it:
            if not self.running:
                break
            if self.speed > 0:  # pace by the capture's own timing
                if first_ts is None:
                    first_ts, wall0 = p.ts, time.time()
                delay = (p.ts - first_ts) / self.speed - (time.time() - wall0)
                if delay > 0.005:
                    await asyncio.sleep(delay)
            while self.queue.full():
                await asyncio.sleep(0.01)  # a replay can wait; live traffic can't
            self._enqueue(p)
            if self.speed <= 0 and self.queue.qsize() % 5000 == 0:
                await asyncio.sleep(0)
        self._source_done = True

    async def _produce_live(self) -> None:
        from .sources.capture import live_capture

        async for p in live_capture(self.iface):
            self._enqueue(p)

    # ------------------------------------------------------------------ processing
    async def _consume(self) -> None:
        proc = self.processor
        while self.running:
            p = await self.queue.get()
            batch = [p]
            while len(batch) < 4000 and not self.queue.empty():
                batch.append(self.queue.get_nowait())
            t0 = time.perf_counter()
            protos: Counter = Counter()
            nbytes = 0
            processed = 0
            for pkt in batch:
                if self.blocklist.check(pkt.src, pkt.dst):
                    m.DROPPED.labels("blocked").inc()
                    self.stats.on_drop()
                    continue
                processed += 1
                nbytes += pkt.size
                protos[pkt.proto] += 1
                for a in proc.process(pkt):
                    self._handle_alert(a)
            m.BATCH_LATENCY.observe(time.perf_counter() - t0)
            m.PACKETS.inc(processed)
            m.BYTES.inc(nbytes)
            m.QUEUE_DEPTH.set(self.queue.qsize())
            if self.source != "pcap":
                m.PIPELINE_LAG.set(max(0.0, time.time() - batch[-1].ts))
            self.stats.on_batch(processed, nbytes, protos, time.time())
            self._last_packet_wall = time.time()
            await asyncio.sleep(0)

    def _on_flow(self, f: Flow) -> None:
        m.FLOWS.inc()
        self.stats.on_flow(f)

    def _handle_alert(self, a: Alert) -> None:
        attacker_geo = self.geo.lookup(a.attacker)
        peer_geo = next((g for g in map(self.geo.lookup, a.peers) if g), None)
        a.enrichment = {
            "attacker_geo": attacker_geo,
            "peer_geo": peer_geo,
            "attacker_asset": self.assets.describe(a.attacker) if a.attacker else None,
            "victim_asset": self.assets.describe(a.victim) if a.victim else None,
        }
        geo = attacker_geo or peer_geo
        self.correlator.ingest(a)
        d = a.to_dict()
        m.ALERTS.labels(a.detector, a.severity.label).inc()
        self.stats.on_alert(a, geo, self.assets.hq)
        self.store.add_alert(d)
        self.recent_alerts.append(d)
        if len(self.recent_alerts) > 500:
            self.recent_alerts = self.recent_alerts[-300:]
        self.bus.publish("alert", d)

    def _on_incident(self, inc: Incident, created: bool) -> None:
        if created:
            m.INCIDENTS.labels(inc.severity.label).inc()
        self._dirty_incidents[inc.id] = inc
        if self.narrator.should_narrate(inc, self.settings.correlation.llm_min_severity):
            task = asyncio.get_running_loop().create_task(self._narrate(inc))
            self._background.add(task)
            task.add_done_callback(self._background.discard)

    async def _narrate(self, inc: Incident) -> None:
        text = await self.narrator.narrate(inc)
        m.LLM_CALLS.labels("ok" if text else "error").inc()
        if text:
            inc.summary, inc.summary_source = text, "llm"
            self._dirty_incidents[inc.id] = inc

    async def _ticker(self) -> None:
        n = 0
        while self.running:
            await asyncio.sleep(1.0)
            n += 1
            # Let flows expire even when traffic goes quiet (event time is close to wall time
            # for live sources).
            if self.source != "pcap" and time.time() - self._last_packet_wall > 1.5:
                for a in self.processor.tick(time.time()):
                    self._handle_alert(a)
            if self._source_done and self.queue.empty():
                for a in self.processor.flush():
                    self._handle_alert(a)
                self._source_done = False
            for inc in self._dirty_incidents.values():
                d = inc.to_dict()
                self.store.upsert_incident(d)
                self.bus.publish("incident", d)
            self._dirty_incidents.clear()
            m.ACTIVE_FLOWS.set(len(self.processor.flows))
            m.OPEN_INCIDENTS.set(len(self.correlator.open_incidents()))
            m.WS_CLIENTS.set(self.bus.subscribers)
            self.bus.publish("stats", self.status())
            if n % 2 == 0:
                self.bus.publish("topology", self.stats.topology())
            if n % 3 == 0:
                await asyncio.to_thread(self.store.flush)

    async def _auto_attacks(self) -> None:
        order = ["apt_killchain", "port_scan", "beaconing", "brute_force", "dns_tunnel", "syn_flood",
                 "lateral_movement", "exfiltration", "ioc_contact"]
        await asyncio.sleep(min(45.0, self.auto_attack))
        i = 0
        while self.running:
            self.launch(order[i % len(order)])
            i += 1
            await asyncio.sleep(self.auto_attack)

    # ------------------------------------------------------------------ control plane
    def launch(self, scenario: str) -> dict[str, Any]:
        if not self.sim:
            raise RuntimeError("attack scenarios are only available with the simulator source")
        camp = self.sim.launch(scenario)
        d = camp.to_dict()
        self.bus.publish("campaign", d)
        log.info("launched %s (%s)", camp.id, scenario)
        return d

    def status(self) -> dict[str, Any]:
        snap = self.stats.snapshot()
        lag = m.PIPELINE_LAG._value.get() if self.source != "pcap" else 0.0
        open_inc = self.correlator.open_incidents()
        return {
            "version": __version__,
            "source": self.source,
            "uptime": round(time.time() - self.started, 1),
            "event_time": self.processor.flows.watermark or time.time(),
            "packets": self.processor.packets,
            "bytes": self.processor.bytes,
            "flows": self.processor.flows_done,
            "active_flows": len(self.processor.flows),
            "alerts": self.processor.alerts,
            "incidents": len(self.correlator.incidents),
            "open_incidents": len(open_inc),
            "threat_level": max((i.risk for i in open_inc), default=0.0),
            "queue_depth": self.queue.qsize(),
            "pipeline_lag": round(lag, 3),
            "blocked": len(self.blocklist),
            "llm": self.narrator.enabled,
            "ml_threshold": self.processor.anomaly.threshold,
            "ml_warmup": max(0, self.settings.detection.anomaly.warmup_flows - self.processor.anomaly.flows_seen),
            "detectors": self.processor.detector_stats(),
            **snap,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "status": self.status(),
            "alerts": self.recent_alerts[-80:],
            "incidents": [i.to_dict() for i in sorted(self.correlator.incidents.values(),
                                                      key=lambda i: -i.last_seen)][:50],
            "topology": self.stats.topology(),
            "geo_events": list(self.stats.geo_events)[-60:],
            "scenarios": SCENARIOS if self.sim else {},
            "campaigns": [c.to_dict() for c in self.sim.campaigns[-20:]] if self.sim else [],
            "blocklist": self.blocklist.list(),
            "hq": self.assets.hq,
            "organization": self.assets.organization,
        }
