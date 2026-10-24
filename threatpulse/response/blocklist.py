"""SOAR-lite response: a block list that the ingest stage enforces.

Blocking an IP drops its traffic before detection, the way a firewall rule would. The
engine also generates the matching ``iptables``/``nft`` commands so an operator can apply the
same block on real infrastructure.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass


@dataclass
class BlockEntry:
    ip: str
    reason: str
    created: float
    expires: float | None
    by: str
    dropped: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["commands"] = [
            f"iptables -I INPUT -s {self.ip} -j DROP",
            f"iptables -I FORWARD -d {self.ip} -j DROP",
            f"nft add element inet filter blocklist {{ {self.ip} }}",
        ]
        return d


class Blocklist:
    def __init__(self):
        self._entries: dict[str, BlockEntry] = {}

    def block(self, ip: str, reason: str = "manual", ttl: float | None = None, by: str = "analyst") -> BlockEntry:
        now = time.time()
        e = BlockEntry(ip=ip, reason=reason, created=now, expires=now + ttl if ttl else None, by=by)
        self._entries[ip] = e
        return e

    def unblock(self, ip: str) -> bool:
        return self._entries.pop(ip, None) is not None

    def check(self, src: str, dst: str) -> BlockEntry | None:
        if not self._entries:
            return None
        e = self._entries.get(src) or self._entries.get(dst)
        if e is None:
            return None
        if e.expires and time.time() > e.expires:
            self._entries.pop(e.ip, None)
            return None
        e.dropped += 1
        return e

    def __len__(self) -> int:
        return len(self._entries)

    def list(self) -> list[dict]:
        return [e.to_dict() for e in sorted(self._entries.values(), key=lambda e: -e.created)]
