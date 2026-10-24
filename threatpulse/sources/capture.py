"""Real traffic sources: PCAP replay and live interface capture through scapy.

scapy is an optional dependency (``pip install threatpulse[capture]``). Live capture needs
root or CAP_NET_RAW.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Iterator

from ..models import Packet

_TCP_FLAG_LETTERS = (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), ("A", 0x10))


def _require_scapy():
    try:
        import scapy.all as scapy  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PCAP/live capture needs scapy: pip install 'threatpulse[capture]'") from exc
    return scapy


def from_scapy(pkt) -> Packet | None:
    """Convert a scapy packet into a ThreatPulse Packet. Returns None for non-IP traffic."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    ts = float(pkt.time)
    size = len(ip)
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        raw = int(t.flags)
        letters = "".join(ch for ch, bit in _TCP_FLAG_LETTERS if raw & bit)
        return Packet(ts, ip.src, ip.dst, int(t.sport), int(t.dport), "TCP", size, _normalise_flags(letters))
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        q = qt = None
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qdcount:
            qd = pkt[DNS].qd
            first = qd[0] if isinstance(qd, list) else qd  # scapy >= 2.6 returns a list
            try:
                q = first.qname.decode(errors="ignore").rstrip(".")
                qt = str(first.qtype)
            except Exception:
                q = None
        return Packet(ts, ip.src, ip.dst, int(u.sport), int(u.dport), "UDP", size, dns_query=q, dns_qtype=qt)
    if pkt.haslayer(ICMP):
        return Packet(ts, ip.src, ip.dst, 0, 0, "ICMP", size)
    return None


def _normalise_flags(f: str) -> str:
    """Use the same flag spellings as the simulator: S, SA, A, PA, FA, R, RA."""
    s = set(f)
    if s == {"S"}:
        return "S"
    if s == {"S", "A"}:
        return "SA"
    out = ""
    for ch in ("P", "F", "R"):
        if ch in s:
            out += ch
    if "A" in s:
        out += "A"
    return out or f


def read_pcap(path: str) -> Iterator[Packet]:
    scapy = _require_scapy()
    with scapy.PcapReader(path) as reader:
        for raw in reader:
            p = from_scapy(raw)
            if p is not None:
                yield p


async def live_capture(iface: str | None, bpf: str | None = "ip or ip6") -> AsyncIterator[Packet]:
    """Sniff in a background thread and hand packets to the event loop."""
    scapy = _require_scapy()
    loop = asyncio.get_running_loop()
    q: asyncio.Queue[Packet] = asyncio.Queue(maxsize=100_000)

    def handle(raw):
        p = from_scapy(raw)
        if p is not None:
            loop.call_soon_threadsafe(lambda: q.full() or q.put_nowait(p))

    sniffer = scapy.AsyncSniffer(iface=iface, filter=bpf, prn=handle, store=False)
    threading.Thread(target=sniffer.start, daemon=True).start()
    try:
        while True:
            yield await q.get()
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass


def write_pcap(packets: list[Packet], path: str) -> int:
    """Export simulator packets to a PCAP that opens in Wireshark."""
    scapy = _require_scapy()
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP

    out = []
    for p in packets:
        if p.proto == "TCP":
            payload = max(0, p.size - 52)
            pkt = IP(src=p.src, dst=p.dst) / TCP(sport=p.sport, dport=p.dport, flags=p.flags or "A") / (b"\x00" * min(payload, 65000))
        elif p.dns_query:
            pkt = IP(src=p.src, dst=p.dst) / UDP(sport=p.sport, dport=p.dport) / DNS(rd=1, qd=DNSQR(qname=p.dns_query))
        else:
            pkt = IP(src=p.src, dst=p.dst) / UDP(sport=p.sport, dport=p.dport) / (b"\x00" * max(0, p.size - 28))
        pkt.time = p.ts
        out.append(pkt)
    scapy.wrpcap(path, out)
    return len(out)
