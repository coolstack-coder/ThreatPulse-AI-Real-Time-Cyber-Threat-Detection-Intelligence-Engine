"""Flow feature vectors for the ML detector.

Half-Space Trees need features in a known bounded range, so each raw feature is log-scaled
into [0, 1] against a fixed ceiling. No data is needed to fit the scaling, which matters for
a detector that has to start scoring on a live stream.
"""

from __future__ import annotations

import math

import numpy as np

from ..models import Flow

# (name, extractor, ceiling). The ceiling is the value that maps to 1.0 after log scaling.
_FEATURES = [
    ("duration", lambda f: f.duration, 600.0),
    ("fwd_bytes", lambda f: f.fwd_bytes, 1e9),
    ("bwd_bytes", lambda f: f.bwd_bytes, 1e9),
    ("fwd_pkts", lambda f: f.fwd_pkts, 1e6),
    ("bwd_pkts", lambda f: f.bwd_pkts, 1e6),
    ("mean_pkt", lambda f: f.total_bytes / max(1, f.total_pkts), 65535.0),
    ("iat_mean", lambda f: f.iat_mean, 60.0),
    ("iat_std", lambda f: f.iat_std, 60.0),
    ("syn_only", lambda f: float(f.syn > 0 and f.synack == 0), 1.0),
    ("rst", lambda f: f.rst, 10.0),
    ("dport", lambda f: _port_class(f.dport), 1.0),
    ("ratio", lambda f: (f.fwd_bytes + 1) / (f.bwd_bytes + 1), 1e4),
]

FEATURE_NAMES = [n for n, _, _ in _FEATURES]
N_FEATURES = len(_FEATURES)


def _port_class(port: int) -> float:
    """Well-known=0, registered=0.5, ephemeral=1. Port numbers are labels, not magnitudes."""
    if port < 1024:
        return 0.0
    if port < 49152:
        return 0.5
    return 1.0


def flow_vector(flow: Flow) -> np.ndarray:
    out = np.empty(N_FEATURES, dtype=np.float64)
    for i, (_, fn, ceiling) in enumerate(_FEATURES):
        v = max(0.0, float(fn(flow)))
        if ceiling == 1.0:
            out[i] = min(1.0, v)
        else:
            out[i] = min(1.0, math.log1p(v) / math.log1p(ceiling))
    return out
