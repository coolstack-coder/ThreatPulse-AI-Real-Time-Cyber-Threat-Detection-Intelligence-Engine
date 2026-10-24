"""Behavioural detectors: C2 beacon periodicity and DNS tunnelling."""

from __future__ import annotations

from collections import Counter, deque

from ..models import Alert, Flow, Packet
from ..netutil import (
    coefficient_of_variation,
    is_internal,
    registered_domain,
    shannon_entropy,
    subdomain,
)
from .base import Detector

_BEACON_EXCLUDED_PORTS = {53, 123, 67, 68, 5353}  # DNS, NTP and DHCP are periodic by design


class BeaconDetector(Detector):
    """Implants check in with their C2 on a timer. Even with jitter, the gaps between check-ins
    have a low coefficient of variation (CV = std/mean), and check-ins tend to be similar in
    size. Requiring the destination to be rare stops popular SaaS heartbeats from firing.
    """

    name = "beaconing"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        self._hist: dict[tuple, deque[tuple[float, int]]] = {}

    def on_flow(self, f: Flow) -> list[Alert] | None:
        c = self.cfg.beacon
        if (f.dport in _BEACON_EXCLUDED_PORTS or f.closed_by == "active"
                or not is_internal(f.src) or is_internal(f.dst)):
            return None
        key = (f.src, f.dst, f.dport)
        h = self._hist.get(key)
        if h is None:
            h = self._hist[key] = deque(maxlen=c.history)
        h.append((f.start, f.total_bytes))
        if len(h) < c.min_events or self.cooling(("beacon", key), f.last, 300):
            return None

        starts = [t for t, _ in h]
        gaps = [b - a for a, b in zip(starts, starts[1:]) if b > a]
        if len(gaps) < c.min_events - 1:
            return None
        mean_gap = sum(gaps) / len(gaps)
        cv = coefficient_of_variation(gaps)
        if mean_gap < c.min_interval or cv > c.max_cv:
            return None
        rarity = self.ctx.rarity(f.dst, f.last)
        if rarity > c.max_rarity or not self.ready(("beacon", key), f.last, 300):
            return None
        size_cv = coefficient_of_variation([float(b) for _, b in h])
        score = 70 + (c.max_cv - cv) / c.max_cv * 15 + (5 if size_cv < 0.3 else 0)
        return [self.alert(
            "beaconing", f.last, f"C2 beaconing {f.src} → {f.dst}:{f.dport}",
            score, attacker=f.src, peers=[f.dst],
            description=(f"{len(h)} connections every {mean_gap:.1f}s (jitter CV {cv:.2f}, size CV "
                         f"{size_cv:.2f}) to a destination only {rarity} internal host(s) contact."),
            evidence={"interval_s": round(mean_gap, 2), "cv": round(cv, 3), "size_cv": round(size_cv, 3),
                      "events": len(h), "rarity": rarity, "dport": f.dport},
            campaigns=f.campaigns,
        )]

    def on_tick(self, now: float) -> None:
        if int(now) % 60:
            return
        for key in [k for k, h in self._hist.items() if not h or now - h[-1][0] > 3600]:
            del self._hist[key]


class DnsTunnelDetector(Detector):
    """Data hidden in DNS names: lots of unique, long, high-entropy labels under one domain."""

    name = "dns_tunnel"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        # (src, registered domain) -> deque of (ts, subdomain, entropy)
        self._q: dict[tuple[str, str], deque] = {}
        self._uniq: dict[tuple[str, str], Counter] = {}

    def on_packet(self, p: Packet) -> list[Alert] | None:
        if not p.dns_query or p.dport != 53:
            return None
        c = self.cfg.dns
        domain = registered_domain(p.dns_query)
        sub = subdomain(p.dns_query)
        if not sub:
            return None
        key = (p.src, domain)
        dq = self._q.setdefault(key, deque())
        uniq = self._uniq.setdefault(key, Counter())
        first_label = sub.split(".")[0]
        dq.append((p.ts, sub, shannon_entropy(first_label), len(first_label)))
        uniq[sub] += 1
        cutoff = p.ts - c.window
        while dq and dq[0][0] < cutoff:
            _, old, _, _ = dq.popleft()
            uniq[old] -= 1
            if not uniq[old]:
                del uniq[old]

        if len(uniq) < min(c.min_unique, c.min_long) or self.cooling(("dns", key), p.ts):
            return None
        avg_entropy = sum(e for _, _, e, _ in dq) / len(dq)
        long_labels = sum(1 for *_, n in dq if n >= c.long_label)
        if not ((len(uniq) >= c.min_unique and avg_entropy >= c.min_entropy) or long_labels >= c.min_long):
            return None
        if not self.ready(("dns", key), p.ts):
            return None
        avg_len = sum(n for *_, n in dq) / len(dq)
        return [self.alert(
            "dns_tunnel", p.ts, f"DNS tunnelling via {domain} from {p.src}",
            72 + min(18, len(uniq) / c.min_unique * 4),
            attacker=p.src, peers=[domain],
            description=(f"{len(uniq)} unique subdomains of {domain} in {c.window:.0f}s; mean label "
                         f"entropy {avg_entropy:.2f} bits/char, mean length {avg_len:.0f}."),
            evidence={"domain": domain, "unique": len(uniq), "entropy": round(avg_entropy, 2),
                      "avg_label_len": round(avg_len, 1), "sample": dq[-1][1][:60]},
        )]

    def on_tick(self, now: float) -> None:
        cutoff = now - self.cfg.dns.window
        for key in [k for k, q in self._q.items() if not q or q[-1][0] < cutoff]:
            del self._q[key]
            del self._uniq[key]
