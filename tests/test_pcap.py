import pytest

pytest.importorskip("scapy")

from threatpulse.config import load_settings  # noqa: E402
from threatpulse.intel.assets import AssetInventory  # noqa: E402
from threatpulse.pipeline.processor import Processor  # noqa: E402
from threatpulse.sources.capture import read_pcap, write_pcap  # noqa: E402
from threatpulse.sources.simulator import TrafficSimulator  # noqa: E402


def test_pcap_round_trip_detects_scan_and_dns_tunnel(tmp_path):
    s = load_settings()
    sim = TrafficSimulator(AssetInventory.load(s.assets_path), seed=2)
    packets = list(sim.run(20))
    for sc in ("port_scan", "dns_tunnel"):
        c = sim.launch(sc)
        packets += list(sim.run(c.end - sim.now + 5))
    path = tmp_path / "demo.pcap"
    write_pcap(packets, str(path))

    replayed = list(read_pcap(str(path)))
    assert len(replayed) == len(packets)
    assert replayed[0].flags == packets[0].flags or packets[0].proto != "TCP"

    proc = Processor(s)
    types = {a.type for p in replayed for a in proc.process(p)}
    assert {"port_scan", "dns_tunnel"} <= types
