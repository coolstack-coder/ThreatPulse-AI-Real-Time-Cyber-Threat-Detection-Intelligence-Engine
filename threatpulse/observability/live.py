"""Rolling, dashboard-friendly statistics: per-second series, top talkers, topology."""

from __future__ import annotations

import time
from collections import Counter, deque

from ..models import Alert, Flow
from ..netutil import is_internal


class LiveStats:
    def __init__(self, history: int = 180):
        self.history = history
        self.series: deque[dict] = deque(maxlen=history)
        self._cur = self._blank(int(time.time()))
        self._talkers: deque[tuple[int, Counter]] = deque(maxlen=60)
        self._edges: deque[tuple[int, Counter]] = deque(maxlen=60)
        self._cur_talkers: Counter = Counter()
        self._cur_edges: Counter = Counter()
        self.proto = Counter()
        self.flagged_edges: dict[tuple[str, str], tuple[float, str]] = {}
        self.severity = Counter()
        self.by_detector = Counter()
        self.geo_events: deque[dict] = deque(maxlen=200)

    @staticmethod
    def _blank(sec: int) -> dict:
        return {"t": sec, "packets": 0, "bytes": 0, "flows": 0, "alerts": 0, "dropped": 0}

    def _roll(self, now: float) -> None:
        sec = int(now)
        if sec != self._cur["t"]:
            self.series.append(self._cur)
            self._talkers.append((self._cur["t"], self._cur_talkers))
            self._edges.append((self._cur["t"], self._cur_edges))
            self._cur = self._blank(sec)
            self._cur_talkers, self._cur_edges = Counter(), Counter()

    def on_batch(self, packets: int, nbytes: int, protos: Counter, now: float) -> None:
        self._roll(now)
        self._cur["packets"] += packets
        self._cur["bytes"] += nbytes
        self.proto.update(protos)

    def on_drop(self, n: int = 1) -> None:
        self._cur["dropped"] += n

    def on_flow(self, f: Flow) -> None:
        self._cur["flows"] += 1
        self._cur_talkers[f.src] += f.total_bytes
        a, b = (f.src, f.dst)
        if not is_internal(a) and not is_internal(b):
            return
        self._cur_edges[(a, b)] += f.total_bytes

    def on_alert(self, a: Alert, geo: dict | None, hq: dict) -> None:
        self._cur["alerts"] += 1
        self.severity[a.severity.label] += 1
        self.by_detector[a.type] += 1
        targets = [a.victim] if a.victim else []
        targets += [p for p in a.peers if p and p[0].isdigit()]
        for t in targets[:10]:
            if a.attacker:
                self.flagged_edges[(a.attacker, t)] = (time.time(), a.severity.label)
        if geo and a.severity.value >= 2:  # low-confidence ML leads stay off the map
            self.geo_events.append({
                "ts": a.ts, "ip": a.attacker if a.attacker and not is_internal(a.attacker) else (a.peers or [""])[0],
                "type": a.type, "severity": a.severity.label, "geo": geo, "hq": hq,
            })

    def snapshot(self) -> dict:
        self._roll(time.time())
        talkers: Counter = Counter()
        for _, c in self._talkers:
            talkers.update(c)
        last = list(self.series)[-5:]
        rate = lambda k: round(sum(s[k] for s in last) / max(1, len(last)), 1)  # noqa: E731
        return {
            "series": list(self.series)[-120:],
            "rates": {"packets": rate("packets"), "bytes": rate("bytes"), "flows": rate("flows"),
                      "alerts": rate("alerts")},
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in talkers.most_common(8)],
            "protocols": dict(self.proto),
            "severity": dict(self.severity),
            "by_detector": dict(self.by_detector),
        }

    def topology(self, limit: int = 70) -> dict:
        edges: Counter = Counter()
        for _, c in self._edges:
            edges.update(c)
        now = time.time()
        self.flagged_edges = {k: v for k, v in self.flagged_edges.items() if now - v[0] < 300}
        top = edges.most_common(limit)
        for k in self.flagged_edges:
            if k not in dict(top):
                top.append((k, edges.get(k, 0)))
        nodes: dict[str, dict] = {}
        out_edges = []
        for (a, b), w in top:
            for n in (a, b):
                nodes.setdefault(n, {"id": n, "internal": is_internal(n), "flagged": False})
            flag = self.flagged_edges.get((a, b))
            if flag:
                nodes[a]["flagged"] = True
            out_edges.append({"source": a, "target": b, "bytes": w, "flagged": flag[1] if flag else None})
        return {"nodes": list(nodes.values()), "edges": out_edges}
