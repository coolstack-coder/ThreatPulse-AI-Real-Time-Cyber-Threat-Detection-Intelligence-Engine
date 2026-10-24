"""Small networking and statistics helpers."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from functools import lru_cache


@lru_cache(maxsize=65536)
def is_internal(ip: str) -> bool:
    """RFC1918, loopback and link-local addresses count as 'inside the perimeter'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def shannon_entropy(s: str) -> float:
    """Bits per character. Random base32/hex labels score roughly 3.5-4.5; English words score lower."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registered_domain(qname: str) -> str:
    """Approximate eTLD+1 ('a.b.evil.com' -> 'evil.com'). Handles common two-part public suffixes."""
    labels = qname.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if labels[-2] in {"co", "com", "org", "net", "ac", "gov"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain(qname: str) -> str:
    reg = registered_domain(qname)
    q = qname.rstrip(".").lower()
    return q[: -len(reg) - 1] if q.endswith("." + reg) else ""


def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return float("inf")
    mean = sum(values) / len(values)
    if mean <= 0:
        return float("inf")
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var) / mean
