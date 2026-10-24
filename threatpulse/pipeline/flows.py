"""Turns a packet stream into bidirectional flows using event time.

A flow is emitted when:
  * TCP closes cleanly (both sides sent FIN) or is reset (RST),
  * it has been idle longer than the protocol's idle timeout (measured against the watermark),
  * it has been open longer than ``active_timeout`` (a partial record is emitted and the flow
    keeps going), or
  * the table is full, in which case the least recently seen flow is evicted.

All timing uses packet timestamps, so a PCAP replay produces the same flows as live capture.
"""

from __future__ import annotations

from collections import OrderedDict

from ..config import FlowConfig
from ..models import Flow, Packet

FlowKey = tuple[str, str, int, str, int]


def flow_key(p: Packet) -> FlowKey:
    a, b = (p.src, p.sport), (p.dst, p.dport)
    lo, hi = (a, b) if a <= b else (b, a)
    return (p.proto, lo[0], lo[1], hi[0], hi[1])


class FlowAssembler:
    def __init__(self, cfg: FlowConfig | None = None):
        self.cfg = cfg or FlowConfig()
        self.table: OrderedDict[FlowKey, Flow] = OrderedDict()
        # Keys of recently closed TCP flows. Trailing ACKs land here instead of opening junk flows.
        self._time_wait: dict[FlowKey, float] = {}
        self.watermark = 0.0
        self._last_sweep = 0.0
        self.emitted = 0
        self.evicted = 0

    def __len__(self) -> int:
        return len(self.table)

    def process(self, p: Packet) -> list[Flow]:
        """Add one packet. Returns any flows that finished as a result."""
        done: list[Flow] = []
        if p.ts > self.watermark:
            self.watermark = p.ts

        key = flow_key(p)
        flow = self.table.get(key)

        if flow is None:
            tw = self._time_wait.get(key)
            if tw is not None and "S" not in p.flags and p.ts - tw < 5.0:
                return done  # straggler after close
            flow = Flow(src=p.src, dst=p.dst, sport=p.sport, dport=p.dport, proto=p.proto,
                        start=p.ts, last=p.ts)
            self.table[key] = flow
            if len(self.table) > self.cfg.max_flows:
                _, old = self.table.popitem(last=False)
                old.closed_by = "evict"
                self.evicted += 1
                done.append(old)
        elif p.ts - flow.start > self.cfg.active_timeout:
            flow.closed_by = "active"
            done.append(flow)
            flow = Flow(src=flow.src, dst=flow.dst, sport=flow.sport, dport=flow.dport,
                        proto=flow.proto, start=p.ts, last=p.ts)
            self.table[key] = flow
            self.table.move_to_end(key)
        else:
            self.table.move_to_end(key)

        self._update(flow, p)

        if p.proto == "TCP" and ("R" in p.flags or flow.fin >= 2):
            flow.closed_by = "rst" if "R" in p.flags else "fin"
            del self.table[key]
            self._time_wait[key] = p.ts
            done.append(flow)

        self.emitted += len(done)
        if self.watermark - self._last_sweep >= self.cfg.sweep_interval:
            done.extend(self.sweep(self.watermark))
        return done

    @staticmethod
    def _update(flow: Flow, p: Packet) -> None:
        if p.ts > flow.last:
            gap = p.ts - flow.last
            flow.iat_n += 1
            delta = gap - flow.iat_mean
            flow.iat_mean += delta / flow.iat_n
            flow.iat_m2 += delta * (gap - flow.iat_mean)
            flow.last = p.ts

        if p.src == flow.src and p.sport == flow.sport:
            flow.fwd_pkts += 1
            flow.fwd_bytes += p.size
            if p.size > flow.fwd_max:
                flow.fwd_max = p.size
        else:
            flow.bwd_pkts += 1
            flow.bwd_bytes += p.size

        f = p.flags
        if f:
            if "S" in f:
                if "A" in f:
                    flow.synack += 1
                else:
                    flow.syn += 1
            if "F" in f:
                flow.fin += 1
            if "R" in f:
                flow.rst += 1
            if "P" in f:
                flow.psh += 1

        if p.dns_query and len(flow.dns_queries) < 32:
            flow.dns_queries.append(p.dns_query)

        flow.labels[p.label] = flow.labels.get(p.label, 0) + 1
        if p.campaign:
            flow.campaigns.add(p.campaign)

    def sweep(self, now: float) -> list[Flow]:
        """Expire idle flows. The table is kept in last-seen order, so the walk stops early."""
        self._last_sweep = now
        cfg = self.cfg
        min_timeout = min(cfg.tcp_idle_timeout, cfg.udp_idle_timeout)
        expired: list[Flow] = []
        stale: list[FlowKey] = []
        for key, flow in self.table.items():
            idle = now - flow.last
            if idle < min_timeout:
                break
            limit = cfg.tcp_idle_timeout if flow.proto == "TCP" else cfg.udp_idle_timeout
            if idle >= limit:
                stale.append(key)
        for key in stale:
            flow = self.table.pop(key)
            flow.closed_by = "idle"
            expired.append(flow)
        self.emitted += len(expired)

        if len(self._time_wait) > 10_000 or (self._time_wait and now % 30 < cfg.sweep_interval):
            self._time_wait = {k: t for k, t in self._time_wait.items() if now - t < 5.0}
        return expired

    def flush(self) -> list[Flow]:
        """Emit every open flow (end of a replay)."""
        out = list(self.table.values())
        for f in out:
            f.closed_by = "flush"
        self.table.clear()
        self.emitted += len(out)
        return out
