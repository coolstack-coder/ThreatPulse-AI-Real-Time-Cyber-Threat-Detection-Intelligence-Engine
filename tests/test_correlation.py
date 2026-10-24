from threatpulse.config import load_settings
from threatpulse.correlation.engine import Correlator
from threatpulse.detection.intel import IocFeed
from threatpulse.intel.assets import AssetInventory
from threatpulse.models import Alert, Severity
from threatpulse.pipeline.processor import Processor
from threatpulse.sources.simulator import TrafficSimulator


def A(type, ts, attacker, victim=None, peers=(), score=70):
    from threatpulse.correlation.mitre import technique_for

    t = technique_for(type)
    return Alert(ts=ts, detector="t", type=type, title=type, severity=Severity.from_score(score), score=score,
                 attacker=attacker, victim=victim, peers=list(peers), tactic=t.tactic, technique=t.id)


def test_pivot_links_external_attacker_to_compromised_host():
    c = Correlator()
    i1 = c.ingest(A("port_scan", 0, "45.155.205.9", "10.0.0.80", score=55))
    i2 = c.ingest(A("brute_force_success", 30, "45.155.205.9", "10.0.0.80", score=92))
    i3 = c.ingest(A("beaconing", 60, "10.0.0.80", peers=["103.75.1.2"], score=80))
    i4 = c.ingest(A("exfiltration", 90, "10.0.0.80", peers=["103.75.1.2"], score=85))
    assert i1 is i2 is i3 is i4
    assert i1.tactics == ["Discovery", "Initial Access", "Command and Control", "Exfiltration"]
    assert i1.compromised == {"10.0.0.80"} and "103.75.1.2" in i1.attackers
    assert i1.severity == Severity.CRITICAL and "Multi-stage" in i1.title


def test_failed_attack_victim_is_not_a_pivot():
    c = Correlator()
    i1 = c.ingest(A("brute_force", 0, "45.155.205.9", "10.0.0.80"))
    i2 = c.ingest(A("beaconing", 10, "10.0.0.80", peers=["103.75.1.2"]))
    assert i1 is not i2


def test_low_confidence_alerts_never_open_incidents():
    c = Correlator()
    assert c.ingest(A("flow_anomaly", 0, "10.0.1.5", score=35)) is None
    assert c.ingest(A("volume_anomaly", 0, "10.0.1.5", score=60)) is None
    assert c.orphans == 2 and not c.incidents


def test_incidents_merge_when_a_shared_entity_appears():
    c = Correlator()
    a = c.ingest(A("beaconing", 0, "10.0.1.20", peers=["196.251.3.3"]))
    b = c.ingest(A("ioc_match", 5, "10.0.1.21", peers=["91.240.118.7"]))
    assert a is not b
    merged = c.ingest(A("exfiltration", 10, "10.0.1.20", peers=["91.240.118.7"]))
    assert len(c.incidents) == 1 and merged.alert_types.keys() >= {"beaconing", "ioc_match", "exfiltration"}


def test_window_expiry_starts_new_incident():
    c = Correlator()
    a = c.ingest(A("port_scan", 0, "45.155.205.9", "10.0.0.80"))
    b = c.ingest(A("port_scan", 5000, "45.155.205.9", "10.0.0.80"))
    assert a is not b


def test_end_to_end_kill_chain_becomes_one_incident():
    s = load_settings()
    assets = AssetInventory.load(s.assets_path)
    sim = TrafficSimulator(assets, seed=11)
    proc = Processor(s, IocFeed.load(s.ioc_path), assets.admin_hosts)
    corr = Correlator(s.correlation, assets)
    for p in sim.run(200):
        for a in proc.process(p):
            corr.ingest(a)
    camp = sim.launch("apt_killchain")
    for p in sim.run(camp.end - sim.now + 30):
        for a in proc.process(p):
            corr.ingest(a)
    apt = [i for i in corr.incidents.values() if camp.id in i.campaigns]
    assert len(apt) == 1, [i.title for i in corr.incidents.values()]
    inc = apt[0]
    assert len(inc.tactics) >= 5
    assert inc.severity == Severity.CRITICAL
    assert "10.0.0.80" in inc.compromised
    # Benign background traffic must not have produced any incident
    assert all(camp.id in i.campaigns for i in corr.incidents.values())
