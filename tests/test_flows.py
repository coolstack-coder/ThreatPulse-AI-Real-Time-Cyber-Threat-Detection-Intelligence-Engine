from threatpulse.config import FlowConfig
from threatpulse.models import Packet
from threatpulse.pipeline.features import N_FEATURES, flow_vector
from threatpulse.pipeline.flows import FlowAssembler


def tcp(ts, src, dst, sport, dport, flags, size=60):
    return Packet(ts=ts, src=src, dst=dst, sport=sport, dport=dport, proto="TCP", size=size, flags=flags)


def handshake_session(t0=0.0):
    c, s = "10.0.1.10", "93.184.216.34"
    return [
        tcp(t0, c, s, 50000, 443, "S"),
        tcp(t0 + 0.01, s, c, 443, 50000, "SA"),
        tcp(t0 + 0.02, c, s, 50000, 443, "A"),
        tcp(t0 + 0.03, c, s, 50000, 443, "PA", 500),
        tcp(t0 + 0.05, s, c, 443, 50000, "PA", 4000),
        tcp(t0 + 0.06, c, s, 50000, 443, "FA"),
        tcp(t0 + 0.07, s, c, 443, 50000, "FA"),
        tcp(t0 + 0.08, c, s, 50000, 443, "A"),  # trailing ACK must not create a new flow
    ]


def test_bidirectional_flow_closes_on_fin():
    fa = FlowAssembler()
    done = []
    for p in handshake_session():
        done += fa.process(p)
    assert len(done) == 1
    f = done[0]
    assert (f.src, f.dport) == ("10.0.1.10", 443)
    assert f.fwd_pkts == 4 and f.bwd_pkts == 3
    assert f.fwd_bytes == 60 * 3 + 500 and f.bwd_bytes == 60 * 2 + 4000
    assert f.syn == 1 and f.synack == 1 and f.closed_by == "fin"
    assert len(fa) == 0


def test_rst_closes_immediately():
    fa = FlowAssembler()
    fa.process(tcp(0, "1.2.3.4", "10.0.0.5", 4000, 22, "S"))
    done = fa.process(tcp(0.01, "10.0.0.5", "1.2.3.4", 22, 4000, "RA"))
    assert len(done) == 1 and done[0].closed_by == "rst"


def test_idle_timeout_uses_event_time():
    fa = FlowAssembler(FlowConfig(udp_idle_timeout=5, tcp_idle_timeout=10))
    fa.process(Packet(0, "10.0.1.2", "10.0.0.53", 5353, 53, "UDP", 80, dns_query="a.example.com"))
    assert fa.process(Packet(3, "10.0.1.3", "8.8.8.8", 1, 2, "UDP", 80)) == []
    done = fa.process(Packet(6, "10.0.1.3", "8.8.8.8", 1, 2, "UDP", 80))
    assert [f.dport for f in done] == [53]
    assert done[0].closed_by == "idle" and done[0].dns_queries == ["a.example.com"]


def test_active_timeout_splits_long_flows():
    fa = FlowAssembler(FlowConfig(active_timeout=10, tcp_idle_timeout=100))
    out = []
    for i in range(25):
        out += fa.process(tcp(i, "10.0.1.2", "5.5.5.5", 1000, 443, "PA", 1000))
    assert [f.closed_by for f in out] == ["active", "active"]


def test_eviction_when_table_full():
    fa = FlowAssembler(FlowConfig(max_flows=3))
    out = []
    for i in range(5):
        out += fa.process(tcp(i * 0.001, "10.0.1.2", "5.5.5.5", 1000 + i, 443, "S"))
    assert len(fa) == 3 and fa.evicted == 2 and all(f.closed_by == "evict" for f in out)


def test_feature_vector_is_bounded():
    fa = FlowAssembler()
    flows = []
    for p in handshake_session():
        flows += fa.process(p)
    v = flow_vector(flows[0])
    assert v.shape == (N_FEATURES,)
    assert ((v >= 0) & (v <= 1)).all()
