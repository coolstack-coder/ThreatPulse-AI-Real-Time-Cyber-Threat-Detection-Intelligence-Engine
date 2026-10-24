"""Labelled network traffic simulator.

Produces a realistic packet stream for a small corporate network: browsing with DNS
lookups, internal SMB and LDAP, a public web tier talking to a database, telemetry
heartbeats, NTP and mail. On top of that it can inject attack campaigns on demand. Every
packet carries a ground-truth label and a campaign id, which the detectors never read but
the evaluation harness uses to measure recall, false positives and time to detect.

Time is virtual. ``advance(t)`` returns every packet up to ``t``, so the same simulator can
run as fast as possible (evaluation and benchmarks) or paced to the wall clock (live demo).
"""

from __future__ import annotations

import heapq
import itertools
import random
import string
from collections.abc import Iterator
from dataclasses import dataclass, field

from ..intel.assets import AssetInventory
from ..models import Packet

SAAS = [  # (ip prefix, domains, weight). Popular destinations that many hosts share.
    ("142.250.", ["www.google.com", "mail.google.com", "docs.google.com", "drive.google.com"], 30),
    ("13.107.", ["outlook.office365.com", "teams.microsoft.com", "login.microsoftonline.com"], 25),
    ("151.101.", ["www.reddit.com", "pypi.org", "cdn.jsdelivr.net"], 10),
    ("104.16.", ["www.cloudflare.com", "discord.com", "cdnjs.cloudflare.com"], 10),
    ("52.95.", ["s3.amazonaws.com", "console.aws.amazon.com"], 10),
    ("157.240.", ["www.facebook.com", "web.whatsapp.com"], 6),
    ("140.82.", ["github.com", "api.github.com"], 9),
]
LONG_TAIL = [("81.2.", "news-site.co.uk"), ("118.27.", "shop.example.jp"), ("1.32.", "blog.example.sg"),
             ("49.36.", "local-portal.in"), ("106.51.", "vendor-portal.in"), ("212.102.", "forum.example.ro")]
TELEMETRY = ("20.190.", "telemetry.vendor-saas.com")
NTP_SERVER = "162.159.200.123"
PUBLIC_CLIENT_PREFIXES = ["49.36.", "106.51.", "81.2.", "118.27.", "1.32.", "142.250.", "52.95."]

ATTACKER_PREFIXES = ["45.155.205.", "185.220.101.", "61.177.172.", "103.75.", "177.54.", "196.251.", "212.102."]
C2_PREFIXES = ["103.75.", "196.251.", "177.54.", "212.102."]

SCENARIOS = {
    "port_scan": "TCP SYN scan of a public server's ports",
    "brute_force": "SSH password guessing that ends in a successful login",
    "syn_flood": "Spoofed-source SYN flood against the web tier",
    "beaconing": "Implant on an internal host checking in with C2 every few seconds",
    "dns_tunnel": "Data smuggled out in high-entropy DNS queries",
    "lateral_movement": "Compromised host fanning out over SMB/RDP",
    "exfiltration": "Bulk upload of data to a rare external host",
    "ioc_contact": "Workstation talks to known-bad infrastructure from the intel feed",
    "apt_killchain": "Full intrusion: scan → brute force → C2 → DNS tunnel → lateral → exfil",
}


@dataclass
class Campaign:
    id: str
    scenario: str
    start: float
    end: float
    actors: set[str] = field(default_factory=set)  # IPs that originate malicious traffic
    victims: set[str] = field(default_factory=set)
    description: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "scenario": self.scenario, "start": self.start, "end": self.end,
                "actors": sorted(self.actors), "victims": sorted(self.victims),
                "description": self.description}


class TrafficSimulator:
    def __init__(self, assets: AssetInventory, seed: int = 42, start: float = 1_700_000_000.0,
                 intensity: float = 1.0):
        self.assets = assets
        self.rng = random.Random(seed)
        self.now = start
        self.start = start
        self.intensity = intensity
        self._heap: list[tuple[float, int, Packet]] = []
        self._seq = itertools.count()
        self._generated_until = start
        self._campaign_ids = itertools.count(1)
        self.campaigns: list[Campaign] = []
        self._ports: dict[str, int] = {}

        self.workstations = [a.ip for a in assets.by_role("workstation")] or [f"10.0.1.{i}" for i in range(10, 50)]
        def first(role: str, default: str) -> str:
            found = assets.by_role(role)
            return found[0].ip if found else default

        self.dns = first("dns", "10.0.0.53")
        self.dc = first("domain-controller", "10.0.0.10")
        self.file = first("file-server", "10.0.0.20")
        self.db = first("database", "10.0.0.30")
        self.mail = first("mail", "10.0.0.25")
        self.jump = first("admin", "10.0.0.5")
        webs = [a.ip for a in assets.by_role("web")] or ["10.0.0.80"]
        self.web = webs
        self.servers = [ip for ip in (self.dc, self.file, self.db, self.mail, self.dns, *webs)]
        # Each host's telemetry heartbeat phase (popular, periodic, benign)
        self._next_telemetry = {h: start + self.rng.uniform(0, 120) for h in self.workstations}
        self._next_ntp = {h: start + self.rng.uniform(0, 64) for h in self.workstations + self.servers}

    # ------------------------------------------------------------------ primitives
    def _ip(self, prefix: str) -> str:
        parts = 4 - prefix.count(".")
        return prefix + ".".join(str(self.rng.randint(1, 254)) for _ in range(parts))

    def _eport(self, host: str) -> int:
        p = self._ports.get(host, self.rng.randint(40000, 50000)) + 1
        if p > 65000:
            p = 40000
        self._ports[host] = p
        return p

    def _emit(self, p: Packet) -> None:
        heapq.heappush(self._heap, (p.ts, next(self._seq), p))

    def _pkt(self, ts, src, dst, sport, dport, proto, size, flags="", label="benign", campaign=None, **kw):
        self._emit(Packet(ts, src, dst, sport, dport, proto, int(size), flags, label=label, campaign=campaign, **kw))

    def tcp_session(self, t: float, c: str, s: str, dport: int, exchanges: list[tuple[int, int]],
                    rtt: float = 0.03, think: float = 0.05, label: str = "benign", campaign: str | None = None,
                    close: str = "fin", sport: int | None = None) -> float:
        """Schedule a full TCP conversation. ``exchanges`` is a list of (request bytes, response bytes)."""
        cp = sport or self._eport(c)
        kw = {"label": label, "campaign": campaign}
        self._pkt(t, c, s, cp, dport, "TCP", 60, "S", **kw)
        self._pkt(t + rtt, s, c, dport, cp, "TCP", 60, "SA", **kw)
        t += rtt + 0.001
        self._pkt(t, c, s, cp, dport, "TCP", 52, "A", **kw)
        for req, resp in exchanges:
            t += self.rng.uniform(0.2, 1.8) * think
            for chunk in _segments(req):
                self._pkt(t, c, s, cp, dport, "TCP", chunk, "PA", **kw)
                t += 0.0008
            t += rtt
            for chunk in _segments(resp):
                self._pkt(t, s, c, dport, cp, "TCP", chunk, "PA", **kw)
                t += 0.0008
        t += 0.01
        if close == "fin":
            self._pkt(t, c, s, cp, dport, "TCP", 52, "FA", **kw)
            self._pkt(t + rtt, s, c, dport, cp, "TCP", 52, "FA", **kw)
        elif close == "rst":
            self._pkt(t, s, c, dport, cp, "TCP", 52, "RA", **kw)
        return t + rtt

    def dns_query(self, t: float, client: str, qname: str, qtype: str = "A", label: str = "benign",
                  campaign: str | None = None) -> float:
        sp = self._eport(client)
        self._pkt(t, client, self.dns, sp, 53, "UDP", 60 + len(qname), dns_query=qname, dns_qtype=qtype,
                  label=label, campaign=campaign)
        self._pkt(t + 0.004, self.dns, client, 53, sp, "UDP", 90 + len(qname) + self.rng.randint(0, 120),
                  label=label, campaign=campaign)
        return t + 0.005

    # ------------------------------------------------------------------ benign traffic
    def _benign_second(self, t0: float) -> None:
        r, k = self.rng, self.intensity
        for ws in self.workstations:
            for _ in range(_poisson(r, 0.22 * k)):
                t = t0 + r.random()
                if r.random() < 0.88:
                    prefix, domains, _ = r.choices(SAAS, weights=[w for *_, w in SAAS])[0]
                    domain = r.choice(domains)
                else:
                    prefix, domain = r.choice(LONG_TAIL)
                dst = prefix + f"{r.randint(0, 3)}.{r.randint(1, 30)}"
                t = self.dns_query(t, ws, domain)
                n = r.randint(1, 6)
                ex = [(r.randint(300, 1400), int(r.lognormvariate(9.0, 1.3))) for _ in range(n)]
                if r.random() < 0.01:  # an occasional legit upload to popular cloud storage
                    ex.append((r.randint(1_000_000, 4_000_000), 2000))
                self.tcp_session(t, ws, dst, 443, ex, rtt=r.uniform(0.01, 0.12))
            if r.random() < 0.015 * k:
                self.tcp_session(t0 + r.random(), ws, self.file, 445,
                                 [(r.randint(200, 900), r.randint(2000, 400_000)) for _ in range(r.randint(2, 8))],
                                 rtt=0.001)
            if r.random() < 0.02 * k:
                self.tcp_session(t0 + r.random(), ws, self.dc, r.choice([389, 88]),
                                 [(r.randint(150, 600), r.randint(200, 3000))], rtt=0.001)
            if t0 >= self._next_telemetry[ws]:
                self.tcp_session(t0 + r.random(), ws, TELEMETRY[0] + "8.9", 443, [(700, 300)])
                self._next_telemetry[ws] = t0 + r.gauss(300, 20)

        for host in list(self._next_ntp):
            if t0 >= self._next_ntp[host]:
                sp = self._eport(host)
                self._pkt(t0 + r.random(), host, NTP_SERVER, sp, 123, "UDP", 90)
                self._pkt(t0 + r.random() + 0.03, NTP_SERVER, host, 123, sp, "UDP", 90)
                self._next_ntp[host] = t0 + 64 + r.uniform(-1, 1)

        # Public web tier: customers on the internet hit web-01/02, which query the database
        for _ in range(_poisson(r, 2.2 * k)):
            t = t0 + r.random()
            client = self._ip(r.choice(PUBLIC_CLIENT_PREFIXES))
            web = r.choice(self.web)
            self.tcp_session(t, client, web, 443,
                             [(r.randint(300, 1200), int(r.lognormvariate(9.5, 1.0))) for _ in range(r.randint(1, 4))],
                             rtt=r.uniform(0.02, 0.2))
            if r.random() < 0.6:
                self.tcp_session(t + 0.01, web, self.db, 5432,
                                 [(r.randint(100, 600), r.randint(200, 20_000)) for _ in range(r.randint(1, 3))],
                                 rtt=0.0005)
        if r.random() < 0.15 * k:
            self.tcp_session(t0 + r.random(), self._ip(r.choice(PUBLIC_CLIENT_PREFIXES)), self.mail, 25,
                             [(r.randint(500, 40_000), 250)], rtt=0.08)
        if r.random() < 0.008 * k:  # admins work from the jump host
            self.tcp_session(t0 + r.random(), self.jump, r.choice(self.servers), 22,
                             [(r.randint(100, 400), r.randint(100, 3000)) for _ in range(r.randint(10, 40))],
                             think=0.4, rtt=0.001)

    # ------------------------------------------------------------------ attacks
    def launch(self, scenario: str, at: float | None = None, **kw) -> Campaign:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; choose from {sorted(SCENARIOS)}")
        t = max(self.now, self._generated_until) + 0.5 if at is None else at
        cid = f"C{next(self._campaign_ids):03d}-{scenario}"
        camp = Campaign(cid, scenario, t, t, description=SCENARIOS[scenario])
        end = getattr(self, f"_atk_{scenario}")(t, camp, **kw)
        camp.end = end
        self.campaigns.append(camp)
        return camp

    def _atk_port_scan(self, t, camp, attacker=None, victim=None, ports=600, rate=120.0):
        a = attacker or self._ip(self.rng.choice(ATTACKER_PREFIXES))
        v = victim or self.rng.choice(self.web)
        camp.actors.add(a)
        camp.victims.add(v)
        open_ports = {22, 80, 443}
        port_list = self.rng.sample(range(1, 10000), ports - 3) + list(open_ports)
        self.rng.shuffle(port_list)
        sp = self.rng.randint(40000, 60000)
        for i, port in enumerate(port_list):
            ts = t + i / rate
            self._pkt(ts, a, v, sp, port, "TCP", 60, "S", label="port_scan", campaign=camp.id)
            if port in open_ports:
                self._pkt(ts + 0.02, v, a, port, sp, "TCP", 60, "SA", label="port_scan", campaign=camp.id)
                self._pkt(ts + 0.04, a, v, sp, port, "TCP", 52, "R", label="port_scan", campaign=camp.id)
            elif self.rng.random() < 0.7:
                self._pkt(ts + 0.02, v, a, port, sp, "TCP", 52, "RA", label="port_scan", campaign=camp.id)
        return t + len(port_list) / rate + 0.1

    def _atk_brute_force(self, t, camp, attacker=None, victim=None, attempts=30, interval=0.7, success=True):
        a = attacker or self._ip(self.rng.choice(ATTACKER_PREFIXES))
        v = victim or self.rng.choice(self.web)
        camp.actors.add(a)
        camp.victims.add(v)
        for i in range(attempts):
            ts = t + i * interval + self.rng.uniform(0, 0.2)
            self.tcp_session(ts, a, v, 22, [(1100, 1200), (300, 90), (300, 90)], rtt=0.09, think=0.05,
                             label="brute_force", campaign=camp.id)
        end = t + attempts * interval + 1.0
        if success:
            end = self.tcp_session(end, a, v, 22,
                                   [(self.rng.randint(80, 300), self.rng.randint(500, 4000)) for _ in range(40)],
                                   rtt=0.09, think=0.6, label="brute_force", campaign=camp.id)
        return end

    def _atk_syn_flood(self, t, camp, victim=None, rate=320.0, duration=14.0):
        v = victim or self.rng.choice(self.web)
        camp.victims.add(v)
        camp.actors.add(f"spoofed→{v}")
        n = int(rate * duration)
        for i in range(n):
            ts = t + i / rate
            src = f"{self.rng.randint(11, 223)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            sp = self.rng.randint(1024, 65000)
            self._pkt(ts, src, v, sp, 443, "TCP", 60, "S", label="syn_flood", campaign=camp.id)
            if self.rng.random() < 0.05:
                self._pkt(ts + 0.01, v, src, 443, sp, "TCP", 60, "SA", label="syn_flood", campaign=camp.id)
        return t + duration

    def _atk_beaconing(self, t, camp, host=None, c2=None, interval=5.0, jitter=0.1, count=24):
        h = host or self.rng.choice(self.workstations)
        c2 = c2 or self._ip(self.rng.choice(C2_PREFIXES))
        camp.actors.update({h, c2})
        self.dns_query(t, h, "cdn-assets-sync.net", label="beaconing", campaign=camp.id)
        ts = t + 0.2
        for _ in range(count):
            self.tcp_session(ts, h, c2, 443, [(self.rng.randint(380, 420), self.rng.randint(1150, 1250))],
                             rtt=0.15, label="beaconing", campaign=camp.id)
            ts += interval * (1 + self.rng.uniform(-jitter, jitter))
        return ts

    def _atk_dns_tunnel(self, t, camp, host=None, domain="dataflow-sync.net", count=120, rate=4.0):
        h = host or self.rng.choice(self.workstations)
        camp.actors.add(h)
        alphabet = string.ascii_lowercase + "234567"
        for i in range(count):
            label = "".join(self.rng.choice(alphabet) for _ in range(self.rng.randint(45, 60)))
            self.dns_query(t + i / rate, h, f"{label}.{i % 97}.{domain}", "TXT", label="dns_tunnel", campaign=camp.id)
        return t + count / rate

    def _atk_lateral_movement(self, t, camp, host=None, targets=10):
        h = host or self.rng.choice(self.workstations)
        camp.actors.add(h)
        pool = [x for x in self.workstations + [self.file, self.dc, self.db] if x != h]
        for i, dst in enumerate(self.rng.sample(pool, targets)):
            port = self.rng.choice([445, 445, 135, 3389, 5985])
            camp.victims.add(dst)
            if self.rng.random() < 0.7:
                self.tcp_session(t + i * 1.2, h, dst, port, [(self.rng.randint(200, 2000), self.rng.randint(200, 3000))],
                                 rtt=0.001, label="lateral_movement", campaign=camp.id)
            else:
                sp = self._eport(h)
                self._pkt(t + i * 1.2, h, dst, sp, port, "TCP", 60, "S", label="lateral_movement", campaign=camp.id)
                self._pkt(t + i * 1.2 + 0.001, dst, h, port, sp, "TCP", 52, "RA", label="lateral_movement",
                          campaign=camp.id)
        return t + targets * 1.2 + 1

    def _atk_exfiltration(self, t, camp, host=None, dst=None, megabytes=40, duration=25.0):
        h = host or self.rng.choice([self.db, self.file])
        d = dst or self._ip(self.rng.choice(C2_PREFIXES))
        camp.actors.update({h, d})
        sp = self._eport(h)
        kw = {"label": "exfiltration", "campaign": camp.id}
        self._pkt(t, h, d, sp, 443, "TCP", 60, "S", **kw)
        self._pkt(t + 0.12, d, h, 443, sp, "TCP", 60, "SA", **kw)
        segs = int(megabytes * 1e6 / 64000)
        for i in range(segs):
            ts = t + 0.2 + i * duration / segs
            self._pkt(ts, h, d, sp, 443, "TCP", 64000, "PA", **kw)
            if i % 4 == 0:
                self._pkt(ts + 0.12, d, h, 443, sp, "TCP", 52, "A", **kw)
        end = t + duration + 0.5
        self._pkt(end, h, d, sp, 443, "TCP", 52, "FA", **kw)
        self._pkt(end + 0.12, d, h, 443, sp, "TCP", 52, "FA", **kw)
        return end + 0.2

    def _atk_ioc_contact(self, t, camp, host=None):
        h = host or self.rng.choice(self.workstations)
        bad = "91.240.118." + str(self.rng.randint(2, 250))
        camp.actors.update({h, bad})
        t = self.dns_query(t, h, "malware-drop.top", label="ioc_contact", campaign=camp.id)
        return self.tcp_session(t, h, bad, 443, [(500, 250_000)], rtt=0.2, label="ioc_contact", campaign=camp.id)

    def _atk_apt_killchain(self, t, camp, attacker=None, victim=None, c2=None):
        """A complete intrusion against one public web server, staged over about 2.5 minutes."""
        a = attacker or self._ip(self.rng.choice(ATTACKER_PREFIXES))
        v = victim or self.web[0]
        c2 = c2 or self._ip(self.rng.choice(C2_PREFIXES))
        camp.actors.update({a, v, c2})  # the victim becomes an actor once compromised
        camp.victims.add(v)
        sub = Campaign(camp.id, camp.scenario, t, t)
        t1 = self._atk_port_scan(t, sub, attacker=a, victim=v, ports=400)
        t2 = self._atk_brute_force(t1 + 4, sub, attacker=a, victim=v, attempts=25, interval=0.6)
        t3 = self._atk_beaconing(t2 + 3, sub, host=v, c2=c2, interval=4.0, count=22)
        self._atk_dns_tunnel(t2 + 25, sub, host=v, domain="cloud-sync-api.net", count=90)
        t4 = self._atk_lateral_movement(t2 + 50, sub, host=v, targets=9)
        t5 = self._atk_exfiltration(max(t3, t4) + 2, sub, host=v, dst=c2, megabytes=35, duration=20)
        camp.victims.update(sub.victims)
        return t5

    # ------------------------------------------------------------------ streaming
    def advance(self, until: float) -> list[Packet]:
        """Generate benign traffic up to ``until`` and return every packet with ts <= until, in order."""
        while self._generated_until < until:
            self._benign_second(self._generated_until)
            self._generated_until += 1.0
        out: list[Packet] = []
        heap = self._heap
        while heap and heap[0][0] <= until:
            out.append(heapq.heappop(heap)[2])
        self.now = until
        return out

    def run(self, duration: float, step: float = 1.0) -> Iterator[Packet]:
        end = self.now + duration
        while self.now < end:
            yield from self.advance(min(end, self.now + step))


def _segments(n: int, mss: int = 64000) -> list[int]:
    """Split a payload into coalesced segments (GRO-style; at most 64 KB each)."""
    if n <= mss:
        return [max(n, 52)]
    full, rem = divmod(n, mss)
    return [mss] * full + ([rem] if rem else [])


def _poisson(r: random.Random, lam: float) -> int:
    # Knuth's method, fine for the small rates used here
    import math

    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= r.random()
        if p <= L:
            return k
        k += 1
