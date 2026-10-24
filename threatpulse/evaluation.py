"""Evaluation harness: measures detection quality against the simulator's ground truth.

For each seed it warms up on benign traffic, measures the false-positive rate on a stretch
of pure benign traffic, then runs every attack scenario in turn and records:

* **recall**: was the campaign detected by at least one alert attributed to its actors?
* **time to detect (TTD)**: event-time seconds from campaign start to the first alert
* **incident quality**: did the campaign end up in a single incident, and which tactics did it cover?
* **false positives**: alerts and incidents that match no campaign, normalised per hour
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from .config import Settings, load_settings
from .correlation.engine import Correlator
from .detection.intel import IocFeed
from .intel.assets import AssetInventory
from .models import Alert, Severity
from .pipeline.processor import Processor
from .sources.simulator import SCENARIOS, Campaign, TrafficSimulator


@dataclass
class ScenarioResult:
    scenario: str
    runs: int = 0
    detected: int = 0
    ttd: list[float] = field(default_factory=list)
    single_incident: int = 0
    tactics: list[int] = field(default_factory=list)
    detectors: set[str] = field(default_factory=set)


def _entities(a: Alert) -> set[str]:
    s = {x for x in (a.attacker, a.victim) if x}
    s.update(a.peers)
    return s


def _matches(a: Alert, c: Campaign) -> bool:
    if c.id in a.campaigns:
        return True
    if not (c.start - 1 <= a.ts <= c.end + 90):
        return False
    keys = set(c.actors)
    if c.scenario == "syn_flood":
        keys |= c.victims
    return bool(_entities(a) & keys)


def evaluate(seeds: int = 3, warmup: float = 240.0, benign: float = 1800.0, gap: float = 40.0,
             settings: Settings | None = None) -> dict:
    settings = settings or load_settings()
    assets = AssetInventory.load(settings.assets_path)
    ioc = IocFeed.load(settings.ioc_path)
    results = {s: ScenarioResult(s) for s in SCENARIOS}
    fp_alerts = fp_incidents = 0
    fp_by_type: dict[str, int] = {}
    benign_hours = 0.0
    packets = 0
    t_start = time.perf_counter()

    for seed in range(seeds):
        sim = TrafficSimulator(assets, seed=1000 + seed)
        proc = Processor(settings, ioc, assets.admin_hosts)
        corr = Correlator(settings.correlation, assets)
        alerts: list[Alert] = []

        def pump(duration: float, record: bool = True):
            nonlocal packets
            for p in sim.run(duration):
                packets += 1
                for a in proc.process(p):
                    corr.ingest(a)
                    if record:
                        alerts.append(a)

        pump(warmup, record=False)  # ML warm-up, not scored
        b0 = sim.now
        pump(benign)
        benign_alerts = [a for a in alerts if a.ts >= b0]
        benign_hours += benign / 3600
        for a in benign_alerts:
            if a.severity >= Severity.MEDIUM:
                fp_alerts += 1
                fp_by_type[a.type] = fp_by_type.get(a.type, 0) + 1
        fp_incidents += len(corr.incidents)

        for scenario in SCENARIOS:
            camp = sim.launch(scenario)
            pump(camp.end - sim.now + gap)
        for a in proc.flush():
            corr.ingest(a)
            alerts.append(a)

        for camp in sim.campaigns:
            r = results[camp.scenario]
            r.runs += 1
            hits = [a for a in alerts if _matches(a, camp) and a.severity >= Severity.MEDIUM]
            if hits:
                r.detected += 1
                r.ttd.append(max(0.0, min(a.ts for a in hits) - camp.start))
                r.detectors |= {a.type for a in hits}
                incs = {a.incident_id for a in hits if a.incident_id}
                if len(incs) == 1:
                    r.single_incident += 1
                    inc_id = next(iter(incs))
                    inc = corr.incidents.get(inc_id)
                    if inc:
                        r.tactics.append(len(inc.tactics))

    elapsed = time.perf_counter() - t_start
    rows = []
    for r in results.values():
        rows.append({
            "scenario": r.scenario,
            "runs": r.runs,
            "recall": round(r.detected / r.runs, 3) if r.runs else 0.0,
            "median_ttd_s": round(statistics.median(r.ttd), 1) if r.ttd else None,
            "single_incident_rate": round(r.single_incident / r.runs, 3) if r.runs else 0.0,
            "max_tactics": max(r.tactics) if r.tactics else 0,
            "detectors": sorted(r.detectors),
        })
    total_runs = sum(r.runs for r in results.values())
    return {
        "seeds": seeds,
        "scenarios": rows,
        "overall_recall": round(sum(r.detected for r in results.values()) / max(1, total_runs), 3),
        "benign_hours": round(benign_hours, 2),
        "false_positive_alerts_per_hour": round(fp_alerts / max(1e-9, benign_hours), 2),
        "false_positive_incidents_per_hour": round(fp_incidents / max(1e-9, benign_hours), 2),
        "false_positives_by_type": fp_by_type,
        "packets": packets,
        "wall_seconds": round(elapsed, 1),
        "packets_per_second": round(packets / elapsed),
    }


def to_markdown(res: dict) -> str:
    lines = [
        "# Detection Evaluation",
        "",
        f"Generated by `threatpulse evaluate --seeds {res['seeds']}`. Every scenario runs once per seed on top of "
        "realistic benign background traffic; ground truth comes from the simulator's labels.",
        "",
        "| Scenario | Runs | Recall | Median time-to-detect | Single incident | Max ATT&CK tactics | Detectors that fired |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in res["scenarios"]:
        ttd = f"{r['median_ttd_s']} s" if r["median_ttd_s"] is not None else "n/a"
        lines.append(f"| `{r['scenario']}` | {r['runs']} | {r['recall']:.0%} | {ttd} | "
                     f"{r['single_incident_rate']:.0%} | {r['max_tactics']} | {', '.join(r['detectors'])} |")
    lines += [
        "",
        f"* **Overall recall:** {res['overall_recall']:.0%}",
        f"* **Benign traffic scored:** {res['benign_hours']} h",
        f"* **False-positive alerts (medium+) per hour:** {res['false_positive_alerts_per_hour']}",
        f"* **False-positive incidents per hour:** {res['false_positive_incidents_per_hour']}",
        f"* **Throughput during evaluation (simulation + detection):** {res['packets_per_second']:,} packets/s "
        f"({res['packets']:,} packets in {res['wall_seconds']} s)",
        "",
        "Time-to-detect is measured in *event time* from the first malicious packet. Some detectors need "
        "evidence to build up before they can fire (beaconing needs about 8 check-ins, exfiltration needs "
        "20 MB), so their latency reflects how the attack itself unfolds.",
    ]
    return "\n".join(lines) + "\n"
