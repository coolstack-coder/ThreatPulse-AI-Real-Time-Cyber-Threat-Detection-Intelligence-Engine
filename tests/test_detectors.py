import random

import numpy as np

from threatpulse.config import DetectionConfig
from threatpulse.detection.anomaly import HalfSpaceTrees, VolumeAnomalyDetector
from threatpulse.detection.base import TrafficContext
from threatpulse.detection.behavior import BeaconDetector, DnsTunnelDetector
from threatpulse.detection.intel import IocDetector, IocFeed
from threatpulse.detection.rules import (
    BruteForceDetector,
    ExfiltrationDetector,
    LateralMovementDetector,
    PortScanDetector,
    SynFloodDetector,
)
from threatpulse.models import Flow, Packet, Severity


def run_packets(det, packets):
    out = []
    for p in packets:
        out += det.on_packet(p) or []
    return out


def run_flows(det, flows):
    out = []
    for f in flows:
        out += det.on_flow(f) or []
    return out


def mkflow(src, dst, dport, start, dur=0.5, fwd=600, bwd=400, proto="TCP"):
    return Flow(src=src, dst=dst, sport=40000, dport=dport, proto=proto, start=start, last=start + dur,
                fwd_bytes=fwd, bwd_bytes=bwd, fwd_pkts=5, bwd_pkts=4)


def det_(cls, **kw):
    return cls(DetectionConfig(), TrafficContext(), **kw)


def test_vertical_port_scan_detected():
    d = det_(PortScanDetector)
    pkts = [Packet(port * 0.02, "45.155.205.7", "10.0.0.80", 55555, port, "TCP", 60, "S") for port in range(1, 200)]
    alerts = run_packets(d, pkts)
    assert len(alerts) == 1  # cooldown suppresses repeats
    a = alerts[0]
    assert a.type == "port_scan" and a.attacker == "45.155.205.7" and a.technique == "T1046"
    assert a.evidence["kind"] == "vertical"


def test_busy_browser_is_not_a_scan():
    d = det_(PortScanDetector)
    pkts = []
    for i in range(60):
        dst = f"151.101.{i}.1"
        pkts.append(Packet(i * 0.1, "10.0.1.20", dst, 50000 + i, 443, "TCP", 60, "S"))
        pkts.append(Packet(i * 0.1 + 0.01, dst, "10.0.1.20", 443, 50000 + i, "TCP", 60, "SA"))
    assert run_packets(d, pkts) == []


def test_syn_flood_detected_with_spoofed_sources():
    d = det_(SynFloodDetector)
    rnd = random.Random(1)
    pkts = [Packet(i / 300, f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.1.1", "10.0.0.80",
                   rnd.randint(1024, 65000), 443, "TCP", 60, "S") for i in range(1500)]
    alerts = run_packets(d, pkts)
    assert alerts and alerts[0].type == "syn_flood" and alerts[0].evidence["spoofed"]
    assert alerts[0].severity >= Severity.HIGH


def test_brute_force_then_success():
    d = det_(BruteForceDetector)
    flows = [mkflow("185.220.101.4", "10.0.0.80", 22, t * 2.0, dur=0.8, fwd=2500, bwd=2000) for t in range(15)]
    flows.append(mkflow("185.220.101.4", "10.0.0.80", 22, 40, dur=20, fwd=40_000, bwd=90_000))
    alerts = run_flows(d, flows)
    types = [a.type for a in alerts]
    assert types == ["brute_force", "brute_force_success"]
    assert alerts[1].severity == Severity.CRITICAL and alerts[1].tactic == "Initial Access"


def test_lateral_movement_and_admin_allowlist():
    flows = [mkflow("10.0.0.80", f"10.0.1.{i}", 445, i) for i in range(10, 18)]
    assert [a.type for a in run_flows(det_(LateralMovementDetector), flows)] == ["lateral_movement"]
    allow = det_(LateralMovementDetector, admin_hosts={"10.0.0.80"})
    assert run_flows(allow, flows) == []


def test_beaconing_requires_periodicity_and_rarity():
    d = det_(BeaconDetector)
    rnd = random.Random(3)
    flows = [mkflow("10.0.0.80", "203.0.113.66", 443, 100 + i * 5 + rnd.uniform(-0.4, 0.4)) for i in range(10)]
    d.ctx.observe(flows[0])
    alerts = run_flows(d, flows)
    assert [a.type for a in alerts] == ["beaconing"]
    assert alerts[0].evidence["cv"] < 0.25

    # Same rhythm towards a destination that 10 hosts use: popular SaaS, so suppressed
    d2 = det_(BeaconDetector)
    for h in range(10):
        d2.ctx.observe(mkflow(f"10.0.1.{h}", "142.250.1.1", 443, 99))
    flows2 = [mkflow("10.0.0.80", "142.250.1.1", 443, 100 + i * 5) for i in range(10)]
    assert run_flows(d2, flows2) == []


def test_random_browsing_is_not_beaconing():
    d = det_(BeaconDetector)
    rnd = random.Random(5)
    t, flows = 0.0, []
    for _ in range(20):
        t += rnd.expovariate(1 / 20)
        flows.append(mkflow("10.0.1.30", "198.51.100.9", 443, t))
    assert run_flows(d, flows) == []


def test_dns_tunnel_detected_but_normal_dns_is_not():
    d = det_(DnsTunnelDetector)
    rnd = random.Random(9)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    tunnel = [Packet(i * 0.5, "10.0.0.80", "10.0.0.53", 5000 + i, 53, "UDP", 120,
                     dns_query="".join(rnd.choice(alphabet) for _ in range(50)) + ".x.evil-cdn.net")
              for i in range(40)]
    alerts = run_packets(d, tunnel)
    assert alerts and alerts[0].type == "dns_tunnel" and alerts[0].evidence["domain"] == "evil-cdn.net"

    normal = [Packet(i * 0.5, "10.0.1.5", "10.0.0.53", 5000 + i, 53, "UDP", 80, dns_query=q)
              for i, q in enumerate(["www.google.com", "mail.google.com", "docs.google.com", "api.github.com"] * 15)]
    assert run_packets(det_(DnsTunnelDetector), normal) == []


def test_exfiltration_to_rare_destination():
    d = det_(ExfiltrationDetector)
    pkts = [Packet(i * 0.05, "10.0.0.30", "203.0.113.200", 50000, 443, "TCP", 64000, "PA") for i in range(400)]
    alerts = run_packets(d, pkts)
    assert [a.type for a in alerts] == ["exfiltration"]
    assert alerts[0].peers == ["203.0.113.200"]


def test_ioc_direction():
    feed = IocFeed()
    feed.add_line("185.220.101.0/24 | tor exit relay")
    feed.add_line("evil-cdn.net | dns tunnel infra")
    d = det_(IocDetector, feed=feed)
    alerts = run_packets(d, [
        Packet(0, "185.220.101.4", "10.0.0.80", 4444, 22, "TCP", 60, "S"),
        Packet(0.01, "10.0.0.80", "185.220.101.4", 22, 4444, "TCP", 60, "SA"),  # reply: ignored
        Packet(1, "10.0.1.9", "10.0.0.53", 5000, 53, "UDP", 80, dns_query="abc.evil-cdn.net"),
    ])
    assert [(a.attacker, a.evidence["kind"]) for a in alerts] == [("185.220.101.4", "ip"), ("10.0.1.9", "domain")]


def test_volume_anomaly():
    d = det_(VolumeAnomalyDetector)
    alerts = []
    t = 0.0
    for bucket in range(12):
        size = 60_000_000 if bucket == 10 else 200_000
        for i in range(20):
            t = bucket * 10 + i * 0.4
            d.on_packet(Packet(t, "10.0.1.7", "52.1.1.1", 1, 443, "TCP", size // 20, "PA"))
        alerts += d.on_tick(bucket * 10 + 10.01) or []
    assert [a.type for a in alerts] == ["volume_anomaly"]


def test_half_space_trees_separates_outliers():
    rng = np.random.default_rng(0)
    hst = HalfSpaceTrees(4, n_trees=25, depth=8, window=128)
    for _ in range(1024):
        hst.learn(np.clip(rng.normal(0.3, 0.03, 4), 0, 1))
    normal = np.mean([hst.score(np.clip(rng.normal(0.3, 0.03, 4), 0, 1)) for _ in range(50)])
    outlier = np.mean([hst.score(np.array([0.95, 0.9, 0.05, 0.9])) for _ in range(5)])
    assert outlier > normal + 0.3
