"""Command-line entry point: ``threatpulse <command>``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path


def _cmd_run(args) -> None:
    import uvicorn

    from .api.app import create_app
    from .config import load_settings
    from .engine import Engine

    settings = load_settings(args.config)
    if args.db:
        settings.db_path = args.db
    engine = Engine(settings, source=args.source, speed=args.speed, seed=args.seed,
                    auto_attack=args.auto_attack, pcap=args.pcap, iface=args.iface, intensity=args.intensity)
    uvicorn.run(create_app(engine), host=args.host, port=args.port, log_level="info")


def _cmd_evaluate(args) -> None:
    from .evaluation import evaluate, to_markdown

    res = evaluate(seeds=args.seeds, benign=args.benign)
    md = to_markdown(res)
    print(md)
    if args.out:
        Path(args.out).write_text(md)
        Path(args.out).with_suffix(".json").write_text(json.dumps(res, indent=2))
        print(f"wrote {args.out}")


def _cmd_benchmark(args) -> None:
    from .config import load_settings
    from .detection.intel import IocFeed
    from .intel.assets import AssetInventory
    from .pipeline.processor import Processor
    from .sources.simulator import TrafficSimulator

    s = load_settings()
    assets = AssetInventory.load(s.assets_path)
    sim = TrafficSimulator(assets, seed=7, intensity=args.intensity)
    print(f"generating {args.seconds:.0f}s of traffic (intensity {args.intensity}) ...")
    packets = list(sim.run(args.seconds))
    for sc in ("port_scan", "syn_flood", "exfiltration"):
        c = sim.launch(sc)
        packets += list(sim.run(c.end - sim.now + 5))
    for ml in (True, False):
        s.detection.anomaly.enabled = ml
        proc = Processor(s, IocFeed.load(s.ioc_path), assets.admin_hosts)
        t0 = time.perf_counter()
        for p in packets:
            proc.process(p)
        dt = time.perf_counter() - t0
        print(f"  ML {'on ' if ml else 'off'}: {len(packets):,} packets, {proc.flows_done:,} flows in {dt:.2f}s "
              f"-> {len(packets) / dt:,.0f} pkt/s, {proc.flows_done / dt:,.0f} flows/s, {proc.alerts} alerts")


def _cmd_export_pcap(args) -> None:
    from .config import load_settings
    from .intel.assets import AssetInventory
    from .sources.capture import write_pcap
    from .sources.simulator import TrafficSimulator

    s = load_settings()
    sim = TrafficSimulator(AssetInventory.load(s.assets_path), seed=args.seed)
    packets = list(sim.run(args.warmup))
    for sc in args.scenario:
        c = sim.launch(sc)
        packets += list(sim.run(c.end - sim.now + 10))
    n = write_pcap(packets, args.out)
    print(f"wrote {n:,} packets to {args.out}")


def _cmd_scenarios(_args) -> None:
    from .sources.simulator import SCENARIOS

    for k, v in SCENARIOS.items():
        print(f"  {k:<18} {v}")


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="threatpulse", description="ThreatPulse AI: real-time threat detection engine")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="start the engine, API and dashboard")
    r.add_argument("--source", choices=["sim", "pcap", "live"], default="sim")
    r.add_argument("--pcap", help="PCAP file to replay (with --source pcap)")
    r.add_argument("--iface", help="interface to sniff (with --source live)")
    r.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier (0 = as fast as possible)")
    r.add_argument("--seed", type=int, default=42)
    r.add_argument("--intensity", type=float, default=1.0, help="benign traffic volume multiplier")
    r.add_argument("--auto-attack", type=float, default=0.0, metavar="SECONDS",
                   help="launch a rotating attack scenario every N seconds (simulator only)")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=8000)
    r.add_argument("--config")
    r.add_argument("--db")
    r.set_defaults(fn=_cmd_run)

    e = sub.add_parser("evaluate", help="measure recall, latency and false positives against ground truth")
    e.add_argument("--seeds", type=int, default=3)
    e.add_argument("--benign", type=float, default=1800.0, help="seconds of benign traffic per seed to score FPs")
    e.add_argument("--out", help="write a markdown report (plus .json)")
    e.set_defaults(fn=_cmd_evaluate)

    b = sub.add_parser("benchmark", help="measure detection throughput")
    b.add_argument("--seconds", type=float, default=300)
    b.add_argument("--intensity", type=float, default=3.0)
    b.set_defaults(fn=_cmd_benchmark)

    x = sub.add_parser("export-pcap", help="write simulated traffic (with attacks) to a PCAP file")
    x.add_argument("--out", default="threatpulse-demo.pcap")
    x.add_argument("--seed", type=int, default=3)
    x.add_argument("--warmup", type=float, default=120)
    x.add_argument("--scenario", nargs="*", default=["apt_killchain"])
    x.set_defaults(fn=_cmd_export_pcap)

    sub.add_parser("scenarios", help="list attack scenarios").set_defaults(fn=_cmd_scenarios)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
