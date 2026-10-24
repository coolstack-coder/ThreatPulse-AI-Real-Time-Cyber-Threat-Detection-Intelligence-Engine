"""Threat-intelligence matching against IOC feeds (IPs, CIDRs and domains)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from ..models import Alert, Packet
from ..netutil import is_internal, registered_domain
from .base import Detector


class IocFeed:
    """A plain-text feed: one indicator per line, ``#`` comments, optional ``| description``."""

    def __init__(self):
        self.ips: dict[str, str] = {}
        self.nets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self.domains: dict[str, str] = {}

    @classmethod
    def load(cls, path: str | Path) -> IocFeed:
        feed = cls()
        p = Path(path)
        if p.exists():
            for line in p.read_text().splitlines():
                feed.add_line(line)
        return feed

    def add_line(self, line: str) -> None:
        line = line.split("#", 1)[0].strip()
        if not line:
            return
        ind, _, desc = (s.strip() for s in line.partition("|"))
        desc = desc or "threat-intel indicator"
        try:
            if "/" in ind:
                self.nets.append((ipaddress.ip_network(ind, strict=False), desc))
            else:
                ipaddress.ip_address(ind)
                self.ips[ind] = desc
        except ValueError:
            self.domains[ind.lower().rstrip(".")] = desc

    def __len__(self) -> int:
        return len(self.ips) + len(self.nets) + len(self.domains)

    def match_ip(self, ip: str) -> str | None:
        if ip in self.ips:
            return self.ips[ip]
        if self.nets:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, desc in self.nets:
                if addr in net:
                    return desc
        return None

    def match_domain(self, qname: str) -> tuple[str, str] | None:
        q = qname.lower().rstrip(".")
        for cand in (q, registered_domain(q)):
            if cand in self.domains:
                return cand, self.domains[cand]
        return None


class IocDetector(Detector):
    name = "threat_intel"

    def __init__(self, cfg, ctx, feed: IocFeed):
        super().__init__(cfg, ctx)
        self.feed = feed
        self._checked: dict[str, str | None] = {}

    def _lookup(self, ip: str) -> str | None:
        if ip in self._checked:
            return self._checked[ip]
        res = None if is_internal(ip) else self.feed.match_ip(ip)
        if len(self._checked) > 100_000:
            self._checked.clear()
        self._checked[ip] = res
        return res

    def on_packet(self, p: Packet) -> list[Alert] | None:
        if not len(self.feed):
            return None
        out: list[Alert] = []
        if p.dns_query:
            hit = self.feed.match_domain(p.dns_query)
            if hit and self.ready(("dom", p.src, hit[0]), p.ts, 300):
                out.append(self.alert(
                    "ioc_match", p.ts, f"Lookup of known-bad domain {hit[0]}", 70,
                    attacker=p.src, peers=[hit[0]],
                    description=f"{p.src} resolved {p.dns_query} ({hit[1]}).",
                    evidence={"indicator": hit[0], "kind": "domain", "intel": hit[1]},
                ))
        # Only look at the initiating packet of a conversation, so replies never flip who the
        # attacker is: TCP SYNs, or UDP sent to a well-known port.
        if p.proto == "TCP":
            if p.flags != "S":
                return out or None
        elif p.proto == "UDP" and p.dport >= 1024 and p.sport < 1024:
            return out or None
        for ip, other in ((p.dst, p.src), (p.src, p.dst)):
            desc = self._lookup(ip)
            if desc and self.ready(("ip", ip, other), p.ts, 300):
                inbound = ip == p.src
                out.append(self.alert(
                    "ioc_match", p.ts,
                    f"{'Inbound traffic from' if inbound else 'Outbound connection to'} known-bad IP {ip}",
                    68 if inbound else 76,
                    attacker=ip if inbound else other,
                    victim=other if inbound else None,
                    peers=[] if inbound else [ip],
                    description=f"Traffic between {other} and {ip}:{p.dport if not inbound else p.sport} ({desc}).",
                    evidence={"indicator": ip, "kind": "ip", "intel": desc, "direction": "in" if inbound else "out"},
                ))
        return out or None
