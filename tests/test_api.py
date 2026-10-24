import time

import pytest
from fastapi.testclient import TestClient

from threatpulse.api.app import create_app
from threatpulse.config import load_settings
from threatpulse.engine import Engine


@pytest.fixture()
def client(tmp_path):
    s = load_settings()
    s.db_path = str(tmp_path / "t.db")
    s.llm.api_key = ""
    engine = Engine(s, source="sim", speed=20.0, seed=5)
    with TestClient(create_app(engine)) as c:
        yield c


def wait_for(fn, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.25)
    raise AssertionError("condition not met")


def test_health_metrics_and_stats(client):
    assert client.get("/api/health").json()["status"] == "ok"
    wait_for(lambda: client.get("/api/stats").json()["packets"] > 1000)
    body = client.get("/metrics").text
    assert "threatpulse_packets_total" in body and "threatpulse_pipeline_lag_seconds" in body


def test_launch_scenario_creates_incident_and_ack(client):
    camp = client.post("/api/scenarios/port_scan").json()
    assert camp["scenario"] == "port_scan"
    incs = wait_for(lambda: client.get("/api/incidents").json())
    inc = incs[0]
    assert "Discovery" in inc["tactics"]
    detail = client.get(f"/api/incidents/{inc['id']}").json()
    assert detail["alerts"] and detail["alerts"][0]["type"] == "port_scan"
    assert client.post(f"/api/incidents/{inc['id']}/status", json={"status": "acknowledged"}).json()["status"] == "acknowledged"
    assert client.post("/api/scenarios/nope").status_code == 404


def test_blocklist_drops_traffic(client):
    r = client.post("/api/blocklist", json={"ip": "10.0.0.80", "reason": "test"})
    assert r.status_code == 200 and "iptables" in r.json()["commands"][0]
    assert client.post("/api/blocklist", json={"ip": "not-an-ip"}).status_code == 422
    wait_for(lambda: client.get("/api/blocklist").json()[0]["dropped"] > 0)
    assert client.delete("/api/blocklist/10.0.0.80").json() == {"unblocked": "10.0.0.80"}


def test_websocket_streams_snapshot_then_batches(client):
    with client.websocket_connect("/ws") as ws:
        first = ws.receive_json()
        assert first["type"] == "snapshot" and "scenarios" in first["data"]
        msg = ws.receive_json()
        assert msg["type"] == "batch" and {m["type"] for m in msg["data"]} & {"stats", "topology", "alert"}
