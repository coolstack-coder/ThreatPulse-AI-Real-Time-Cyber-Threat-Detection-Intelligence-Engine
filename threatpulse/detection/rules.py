"""Stateful rule detectors built on sliding windows.

Each detector encodes how an attack looks on the wire, not a byte signature, so it still
works on encrypted traffic.
"""

from __future__ import annotations

from collections import Counter, deque

from ..models import Alert, Flow, Packet
from ..netutil import is_internal
from .base import Detector, WindowedCounter, WindowedSet


class PortScanDetector(Detector):
    """One source probing many ports (vertical) or many hosts (horizontal), with few replies.

    The reply ratio is the key filter: a busy browser opens many connections too, but nearly
    all of them get a SYN-ACK. A scan mostly gets silence or RSTs.
    """

    name = "port_scan"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        self._probes: dict[str, WindowedSet] = {}
        self._syns: dict[str, WindowedCounter] = {}
        self._replies: dict[str, WindowedCounter] = {}

    def on_packet(self, p: Packet) -> list[Alert] | None:
        c = self.cfg.scan
        if p.proto == "TCP":
            if p.flags == "SA":
                self._replies.setdefault(p.dst, WindowedCounter(c.window)).add(p.ts)
                return None
            if p.flags != "S":
                return None
        elif p.proto != "UDP" or p.dport in (53, 123) or p.sport < 1024:
            return None  # UDP replies come from well-known ports; probes come from ephemeral ones

        probes = self._probes.get(p.src)
        if probes is None:
            probes = self._probes[p.src] = WindowedSet(c.window)
        probes.add(p.ts, (p.dst, p.dport))
        syns = self._syns.setdefault(p.src, WindowedCounter(c.window)).add(p.ts)

        if len(probes) < min(c.vertical_ports, c.horizontal_targets) or self.cooling(("scan", p.src), p.ts):
            return None

        per_host = Counter(dst for dst, _ in probes.items())
        top_host, top_ports = per_host.most_common(1)[0]
        per_port = Counter(port for _, port in probes.items())
        top_port, top_hosts = per_port.most_common(1)[0]
        vertical = top_ports >= c.vertical_ports
        horizontal = top_hosts >= c.horizontal_targets
        if not (vertical or horizontal):
            return None

        rep = self._replies.get(p.src)
        if rep:
            rep.expire(p.ts)
        reply_ratio = (rep.total if rep else 0) / max(1.0, syns)
        if p.proto == "TCP" and reply_ratio > 0.5:
            return None
        if not self.ready(("scan", p.src), p.ts):
            return None

        kind = "vertical" if vertical else "horizontal"
        distinct = len(probes)
        return [self.alert(
            "port_scan", p.ts,
            f"{kind.title()} port scan from {p.src}",
            55 + min(30, distinct / 8),
            attacker=p.src,
            victim=top_host if vertical else None,
            peers=[top_host] if vertical else sorted(per_host)[:10],
            description=(f"{p.src} probed {distinct} host:port pairs in {c.window:.0f}s "
                         f"({top_ports} ports on {top_host}; reply ratio {reply_ratio:.0%})."),
            evidence={"kind": kind, "distinct_probes": distinct, "top_host": top_host,
                      "top_host_ports": top_ports, "top_port": top_port, "top_port_hosts": top_hosts,
                      "reply_ratio": round(reply_ratio, 3)},
        )]

    def on_tick(self, now: float) -> None:
        for table in (self._probes, self._syns, self._replies):
            for key in [k for k, w in table.items() if (w.expire(now) or len(w) == 0)]:
                del table[key]


class SynFloodDetector(Detector):
    """Many SYNs against one target with few SYN-ACKs back: the server's backlog is exhausted."""

    name = "syn_flood"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        self._syn: dict[str, deque[tuple[float, str]]] = {}
        self._src_counts: dict[str, Counter] = {}
        self._synack: dict[str, WindowedCounter] = {}

    def on_packet(self, p: Packet) -> list[Alert] | None:
        if p.proto != "TCP":
            return None
        c = self.cfg.flood
        # Keyed by service (host, port): a flood hammers one port, while a scan spreads out.
        if p.flags == "SA":
            self._synack.setdefault((p.src, p.sport), WindowedCounter(c.window)).add(p.ts)
            return None
        if p.flags != "S":
            return None

        svc = (p.dst, p.dport)
        dq = self._syn.setdefault(svc, deque())
        srcs = self._src_counts.setdefault(svc, Counter())
        dq.append((p.ts, p.src))
        srcs[p.src] += 1
        cutoff = p.ts - c.window
        while dq and dq[0][0] < cutoff:
            _, old = dq.popleft()
            srcs[old] -= 1
            if not srcs[old]:
                del srcs[old]

        n = len(dq)
        if n < c.min_syn:
            return None
        sa = self._synack.get(svc)
        if sa:
            sa.expire(p.ts)
        ratio = (sa.total if sa else 0) / n
        if ratio > c.max_synack_ratio or not self.ready(("flood", svc), p.ts):
            return None

        spoofed = len(srcs) > 50
        attacker = f"spoofed→{p.dst}" if spoofed else srcs.most_common(1)[0][0]
        return [self.alert(
            "syn_flood", p.ts, f"SYN flood against {p.dst}:{p.dport}",
            78 + min(17, n / c.min_syn * 3),
            attacker=attacker, victim=p.dst,
            peers=[s for s, _ in srcs.most_common(5)],
            description=(f"{n} SYNs in {c.window:.0f}s to {p.dst}:{p.dport} from {len(srcs)} sources; "
                         f"only {ratio:.0%} answered."),
            evidence={"syn_rate": round(n / c.window, 1), "sources": len(srcs), "synack_ratio": round(ratio, 3),
                      "spoofed": spoofed, "port": p.dport},
        )]

    def on_tick(self, now: float) -> None:
        cutoff = now - self.cfg.flood.window
        for svc in [k for k, q in self._syn.items() if not q or q[-1][0] < cutoff]:
            del self._syn[svc]
            self._src_counts.pop(svc, None)
            self._synack.pop(svc, None)


class BruteForceDetector(Detector):
    """Bursts of short, small sessions to an authentication service. A long, data-heavy session
    from the same source right after a burst means the attacker probably got in."""

    name = "brute_force"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        self._attempts: dict[tuple, WindowedCounter] = {}
        self._bursts: dict[tuple, float] = {}  # (src, dst, port) -> ts of the brute-force alert

    def on_flow(self, f: Flow) -> list[Alert] | None:
        c = self.cfg.brute_force
        if f.proto != "TCP" or f.dport not in c.auth_ports:
            return None
        key = (f.src, f.dst, f.dport)

        burst_ts = self._bursts.get(key)
        if (burst_ts is not None and f.last - burst_ts < 600
                and f.duration >= c.success_min_duration and f.total_bytes >= c.success_min_bytes):
            del self._bursts[key]
            return [self.alert(
                "brute_force_success", f.last,
                f"Probable successful login on {f.dst}:{f.dport} after brute force",
                92, attacker=f.src, victim=f.dst,
                description=(f"After a brute-force burst, {f.src} held a {f.duration:.0f}s session "
                             f"moving {f.total_bytes / 1e3:.0f} KB to {f.dst}:{f.dport}."),
                evidence={"duration": round(f.duration, 1), "bytes": f.total_bytes, "port": f.dport},
                campaigns=f.campaigns,
            )]

        if f.fwd_bytes > c.max_attempt_bytes or f.duration >= c.success_min_duration:
            return None
        n = self._attempts.setdefault(key, WindowedCounter(c.window)).add(f.last)
        if n < c.min_attempts or not self.ready(("bf", key), f.last):
            return None
        self._bursts[key] = f.last
        return [self.alert(
            "brute_force", f.last, f"Brute force against {f.dst}:{f.dport}",
            62 + min(20, n / c.min_attempts * 4),
            attacker=f.src, victim=f.dst,
            description=f"{int(n)} short authentication attempts from {f.src} to {f.dst}:{f.dport} in {c.window:.0f}s.",
            evidence={"attempts": int(n), "port": f.dport, "window_s": c.window},
            campaigns=f.campaigns,
        )]

    def on_tick(self, now: float) -> None:
        for key in [k for k, w in self._attempts.items() if (w.expire(now) or len(w) == 0)]:
            del self._attempts[key]


class LateralMovementDetector(Detector):
    """An internal host fanning out to many internal peers over admin protocols (SMB/RDP/WinRM/SSH)."""

    name = "lateral_movement"

    def __init__(self, cfg, ctx, admin_hosts: set[str] | None = None):
        super().__init__(cfg, ctx)
        self.admin_hosts = admin_hosts or set()
        self._targets: dict[str, WindowedSet] = {}

    def on_flow(self, f: Flow) -> list[Alert] | None:
        c = self.cfg.lateral
        if (f.dport not in c.admin_ports or f.src in self.admin_hosts
                or not is_internal(f.src) or not is_internal(f.dst)):
            return None
        ws = self._targets.setdefault(f.src, WindowedSet(c.window))
        ws.add(f.last, f.dst)
        if len(ws) < c.min_targets or not self.ready(("lat", f.src), f.last):
            return None
        targets = sorted(ws.items())
        return [self.alert(
            "lateral_movement", f.last, f"Lateral movement from {f.src}",
            74 + min(16, len(targets) * 1.5),
            attacker=f.src, peers=targets[:20],
            description=(f"{f.src} opened admin-protocol sessions to {len(targets)} internal hosts "
                         f"in {c.window:.0f}s (latest {f.dst}:{f.dport})."),
            evidence={"targets": len(targets), "ports": sorted({f.dport}), "sample": targets[:8]},
            campaigns=f.campaigns,
        )]

    def on_tick(self, now: float) -> None:
        for key in [k for k, w in self._targets.items() if (w.expire(now) or len(w) == 0)]:
            del self._targets[key]


class ExfiltrationDetector(Detector):
    """Heavily one-sided outbound transfer to a destination that almost nobody else talks to.

    Counted per packet in 10-second buckets, so a long transfer is caught while it is still
    running instead of when the flow finally closes.
    """

    name = "exfiltration"
    BUCKET = 10.0

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        # (src, dst) -> deque of [bucket_start, out_bytes, in_bytes]
        self._pairs: dict[tuple[str, str], deque] = {}
        self._sums: dict[tuple[str, str], list[float]] = {}

    def on_packet(self, p: Packet) -> list[Alert] | None:
        si, di = is_internal(p.src), is_internal(p.dst)
        if si == di:
            return None
        key, outbound = ((p.src, p.dst), True) if si else ((p.dst, p.src), False)
        c = self.cfg.exfil
        dq = self._pairs.get(key)
        if dq is None:
            dq = self._pairs[key] = deque()
            self._sums[key] = [0.0, 0.0]
        sums = self._sums[key]
        b = p.ts - p.ts % self.BUCKET
        if not dq or dq[-1][0] != b:
            dq.append([b, 0, 0])
        if outbound:
            dq[-1][1] += p.size
            sums[0] += p.size
        else:
            dq[-1][2] += p.size
            sums[1] += p.size
        cutoff = p.ts - c.window
        while dq and dq[0][0] < cutoff:
            _, o, i = dq.popleft()
            sums[0] -= o
            sums[1] -= i

        if not outbound or sums[0] < c.min_bytes:
            return None
        ratio = sums[0] / max(1.0, sums[1])
        if ratio < c.min_ratio:
            return None
        rarity = self.ctx.rarity(key[1], p.ts)
        if rarity > c.max_rarity or not self.ready(("exfil", key), p.ts, 300):
            return None
        mb = sums[0] / 1e6
        return [self.alert(
            "exfiltration", p.ts, f"Possible data exfiltration {key[0]} → {key[1]}",
            80 + min(15, mb / 20),
            attacker=key[0], victim=None, peers=[key[1]],
            description=(f"{key[0]} sent {mb:.1f} MB to {key[1]} in the last {c.window / 60:.0f} min "
                         f"(out/in ratio {ratio:.0f}x). Destination is contacted by {rarity} internal host(s)."),
            evidence={"megabytes": round(mb, 2), "ratio": round(ratio, 1), "rarity": rarity, "dport": p.dport},
        )]

    def on_tick(self, now: float) -> None:
        cutoff = now - self.cfg.exfil.window
        for key in [k for k, q in self._pairs.items() if not q or q[-1][0] < cutoff]:
            del self._pairs[key]
            del self._sums[key]
