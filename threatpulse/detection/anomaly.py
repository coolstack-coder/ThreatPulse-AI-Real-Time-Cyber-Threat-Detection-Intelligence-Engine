"""Unsupervised, streaming anomaly detection.

* ``HalfSpaceTrees``: Streaming Half-Space Trees (Tan, Ting & Liu, IJCAI 2011), written from
  scratch with numpy and vectorised across trees. The tree structure is random and built
  without seeing any data. Each node counts how many points fell into it ("mass") over two
  alternating windows: the *reference* window scores points while the *latest* window
  learns. Points that land in sparsely populated regions score high. Memory stays constant
  and the model adapts to drift by itself.
* ``FlowAnomalyDetector`` runs HST on flow feature vectors and adapts its alert threshold.
* ``VolumeAnomalyDetector`` keeps an EWMA baseline of each host's outbound bytes and flags
  large z-score spikes.
"""

from __future__ import annotations

from collections import deque

import numpy as np

from ..models import Alert, Flow, Packet
from ..netutil import is_internal
from ..pipeline.features import FEATURE_NAMES, N_FEATURES, flow_vector
from .base import Detector


class HalfSpaceTrees:
    def __init__(self, n_features: int, n_trees: int = 25, depth: int = 10, window: int = 256,
                 size_limit: float | None = None, seed: int = 7):
        self.n_features = n_features
        self.n_trees = n_trees
        self.depth = depth
        self.window = window
        self.size_limit = size_limit if size_limit is not None else 0.1 * window
        n_internal = 2 ** depth - 1
        n_nodes = 2 ** (depth + 1) - 1
        rng = np.random.default_rng(seed)

        self.split_dim = np.zeros((n_trees, n_internal), dtype=np.int64)
        self.split_val = np.zeros((n_trees, n_internal), dtype=np.float64)
        for t in range(n_trees):
            # Random "work space" around each dimension (the paper's perturbed ranges)
            s = rng.random(n_features)
            span = 2.0 * np.maximum(s, 1.0 - s)
            self._build(t, 0, s - span, s + span, rng)

        self.ref = np.zeros((n_trees, n_nodes), dtype=np.float64)
        self.latest = np.zeros((n_trees, n_nodes), dtype=np.float64)
        self._rows = np.arange(n_trees)[:, None]
        self._depth_scale = 2.0 ** np.arange(depth + 1)
        self.seen = 0
        self.ready = False

    def _build(self, t: int, node: int, lo: np.ndarray, hi: np.ndarray, rng) -> None:
        if node >= self.split_dim.shape[1]:
            return
        q = int(rng.integers(self.n_features))
        mid = (lo[q] + hi[q]) / 2.0
        self.split_dim[t, node] = q
        self.split_val[t, node] = mid
        hi_left = hi.copy()
        hi_left[q] = mid
        lo_right = lo.copy()
        lo_right[q] = mid
        self._build(t, 2 * node + 1, lo, hi_left, rng)
        self._build(t, 2 * node + 2, lo_right, hi, rng)

    def _paths(self, x: np.ndarray) -> np.ndarray:
        """Node index at every depth, for every tree: shape (trees, depth + 1)."""
        trees = np.arange(self.n_trees)
        idx = np.zeros(self.n_trees, dtype=np.int64)
        path = np.empty((self.n_trees, self.depth + 1), dtype=np.int64)
        path[:, 0] = idx
        for d in range(1, self.depth + 1):
            q = self.split_dim[trees, idx]
            right = x[q] >= self.split_val[trees, idx]
            idx = 2 * idx + 1 + right
            path[:, d] = idx
        return path

    def score(self, x: np.ndarray, path: np.ndarray | None = None) -> float:
        """Anomaly score in [0, 1]. Higher means more anomalous. Returns 0 until the first window fills."""
        if not self.ready:
            return 0.0
        path = self._paths(x) if path is None else path
        mass = self.ref[self._rows, path]  # (trees, depth+1)
        sparse = mass < self.size_limit
        term = np.where(sparse.any(axis=1), sparse.argmax(axis=1), self.depth)
        m = mass[np.arange(self.n_trees), term] * self._depth_scale[term]
        # Log-normalise: a dense region reaches mass * 2^depth ~ window * 2^depth per tree,
        # while an isolated point stops near the root with almost no mass.
        top = np.log1p(self.window * 2.0 ** self.depth)
        return float(np.clip(1.0 - np.log1p(m.mean()) / top, 0.0, 1.0))

    def learn(self, x: np.ndarray, path: np.ndarray | None = None) -> None:
        path = self._paths(x) if path is None else path
        self.latest[self._rows, path] += 1.0
        self.seen += 1
        if self.seen % self.window == 0:
            self.ref, self.latest = self.latest, self.ref
            self.latest.fill(0.0)
            self.ready = True

    def score_learn(self, x: np.ndarray, learn: bool = True) -> float:
        path = self._paths(x)
        s = self.score(x, path)
        if learn:
            self.learn(x, path)
        return s


class FlowAnomalyDetector(Detector):
    """Scores every finished flow with HST.

    The alert threshold is a high quantile of recent scores, so it tracks the network's
    normal behaviour. Flows above the threshold are not learned from, which protects the
    model from being trained on the attack.
    """

    name = "ml_anomaly"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        a = cfg.anomaly
        self.model = HalfSpaceTrees(N_FEATURES, a.trees, a.depth, a.window)
        self._scores: deque[float] = deque(maxlen=5000)
        self.threshold: float | None = None
        self._baseline = np.full(N_FEATURES, 0.5)
        self._global: deque[float] = deque()
        self.flows_seen = 0

    def on_flow(self, f: Flow) -> list[Alert] | None:
        a = self.cfg.anomaly
        if not a.enabled:
            return None
        x = flow_vector(f)
        self.flows_seen += 1
        path = self.model._paths(x)
        s = self.model.score(x, path)

        if self.flows_seen <= a.warmup_flows:
            self.model.learn(x, path)
            if self.model.ready:
                self._scores.append(s)
            self._baseline += 0.01 * (x - self._baseline)
            if self.flows_seen == a.warmup_flows:
                self._recompute_threshold()
            return None

        if self.threshold is None:
            self._recompute_threshold()
        anomalous = s > (self.threshold or 1.0)
        if not anomalous:
            self.model.learn(x, path)
            self._scores.append(s)
            self._baseline += 0.01 * (x - self._baseline)
            if self.flows_seen % 500 == 0:
                self._recompute_threshold()
            return None

        if self.cooling(("ml", f.src), f.last, a.cooldown):
            return None
        # Global rate limit: ML findings are leads, so cap them to avoid flooding analysts.
        while self._global and f.last - self._global[0] > 60:
            self._global.popleft()
        if len(self._global) >= 6:
            return None
        self.ready(("ml", f.src), f.last, a.cooldown)
        self._global.append(f.last)

        dev = np.abs(x - self._baseline)
        top = [FEATURE_NAMES[i] for i in np.argsort(dev)[::-1][:3]]
        thr = self.threshold or 0.0
        sev_score = 30 + 28 * (s - thr) / max(1e-6, 1 - thr)
        return [self.alert(
            "flow_anomaly", f.last, f"Anomalous flow {f.src} → {f.dst}:{f.dport}",
            sev_score, attacker=f.src, victim=f.dst if is_internal(f.dst) else None,
            peers=[] if is_internal(f.dst) else [f.dst],
            description=(f"Half-Space-Trees score {s:.3f} exceeds adaptive threshold {thr:.3f}. "
                         f"Most unusual features: {', '.join(top)}."),
            evidence={"score": round(s, 4), "threshold": round(thr, 4), "top_features": top,
                      "flow": f.summary()},
            campaigns=f.campaigns,
        )]

    def _recompute_threshold(self) -> None:
        if len(self._scores) >= 100:
            q = float(np.quantile(np.fromiter(self._scores, float), self.cfg.anomaly.quantile))
            # Floor the threshold so a very uniform network doesn't alert on tiny deviations.
            self.threshold = max(q, 0.15)


class VolumeAnomalyDetector(Detector):
    """Per-host outbound byte volume compared against its own EWMA mean and variance."""

    name = "volume_anomaly"

    def __init__(self, cfg, ctx):
        super().__init__(cfg, ctx)
        self._current: dict[str, float] = {}
        self._bucket_start: float | None = None
        self._stats: dict[str, list[float]] = {}  # host -> [mean, var, buckets_seen]

    def on_packet(self, p: Packet) -> list[Alert] | None:
        if not is_internal(p.src) or is_internal(p.dst):
            return None
        if self._bucket_start is None:
            self._bucket_start = p.ts - p.ts % self.cfg.volume.bucket
        self._current[p.src] = self._current.get(p.src, 0.0) + p.size
        return None

    def on_tick(self, now: float) -> list[Alert] | None:
        v = self.cfg.volume
        if self._bucket_start is None or now - self._bucket_start < v.bucket:
            return None
        bucket_end = self._bucket_start + v.bucket
        self._bucket_start = now - now % v.bucket
        current, self._current = self._current, {}
        out: list[Alert] = []
        for host in set(self._stats) | set(current):
            x = current.get(host, 0.0)
            st = self._stats.get(host)
            if st is None:
                self._stats[host] = [x, (x * 0.5) ** 2 + 1.0, 1]
                continue
            mean, var, n = st
            std = max(var ** 0.5, 50_000.0)
            z = (x - mean) / std
            if n >= v.warmup_buckets and z >= v.z_threshold and x >= v.min_bytes:
                if self.ready(("vol", host), bucket_end, 120):
                    out.append(self.alert(
                        "volume_anomaly", bucket_end, f"Outbound volume spike from {host}",
                        48 + min(20, z / v.z_threshold * 4),
                        attacker=host,
                        description=(f"{host} sent {x / 1e6:.1f} MB in {v.bucket:.0f}s against a baseline "
                                     f"of {mean / 1e6:.2f} MB (z = {z:.1f})."),
                        evidence={"bytes": int(x), "baseline_mean": int(mean), "z": round(z, 1)},
                    ))
                # Don't absorb an extreme outlier into the baseline.
                st[2] = n + 1
                continue
            diff = x - mean
            incr = v.alpha * diff
            st[0] = mean + incr
            st[1] = (1 - v.alpha) * (var + diff * incr)
            st[2] = n + 1
        return out or None
