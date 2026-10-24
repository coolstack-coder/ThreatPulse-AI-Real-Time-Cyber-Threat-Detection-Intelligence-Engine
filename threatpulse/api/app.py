"""HTTP and WebSocket API, which also serves the built dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from .. import __version__
from ..engine import Engine
from ..observability.metrics import REGISTRY

DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual block from dashboard"
    ttl: float | None = Field(default=None, ge=1, description="Seconds until the block expires")


class StatusRequest(BaseModel):
    status: str = Field(pattern="^(open|acknowledged|resolved)$")


def create_app(engine: Engine) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await engine.start()
        try:
            yield
        finally:
            await engine.stop()

    app = FastAPI(title="ThreatPulse AI", version=__version__, lifespan=lifespan,
                  description="Real-time cyber threat detection and intelligence engine")
    app.state.engine = engine

    # ------------------------------------------------------------ health and telemetry
    @app.get("/api/health")
    def health():
        tasks = {t.get_name(): not t.done() for t in engine._tasks}
        ok = engine.running and all(v for k, v in tasks.items() if k != "producer" or engine.source != "pcap")
        return JSONResponse({"status": "ok" if ok else "degraded", "tasks": tasks, "version": __version__},
                            status_code=200 if ok else 503)

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    @app.get("/api/stats")
    def stats():
        return engine.status()

    @app.get("/api/snapshot")
    def snapshot():
        return engine.snapshot()

    # ------------------------------------------------------------ alerts and incidents
    @app.get("/api/alerts")
    def alerts(limit: int = Query(100, le=1000), severity: str | None = None, type: str | None = None):
        rows = list(reversed(engine.recent_alerts))
        if severity:
            rows = [a for a in rows if a["severity"] == severity]
        if type:
            rows = [a for a in rows if a["type"] == type]
        if len(rows) < limit and not (severity or type):
            seen = {a["id"] for a in rows}
            rows += [a for a in engine.store.recent_alerts(limit) if a["id"] not in seen]
        return rows[:limit]

    @app.get("/api/incidents")
    def incidents(status: str | None = None):
        rows = sorted(engine.correlator.incidents.values(), key=lambda i: -i.last_seen)
        return [i.to_dict() for i in rows if not status or i.status == status]

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str):
        inc = engine.correlator.incidents.get(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        alerts = [a for a in engine.recent_alerts if a.get("incident_id") == incident_id]
        if len(alerts) < len(inc.alert_ids):
            engine.store.flush()
            alerts = engine.store.recent_alerts(500, incident_id=incident_id)
        return {**inc.to_dict(), "alerts": sorted(alerts, key=lambda a: a["ts"])}

    @app.post("/api/incidents/{incident_id}/status")
    def set_status(incident_id: str, body: StatusRequest):
        inc = engine.correlator.set_status(incident_id, body.status)
        if not inc:
            raise HTTPException(404, "incident not found")
        return inc.to_dict()

    # ------------------------------------------------------------ response
    @app.get("/api/blocklist")
    def blocklist():
        return engine.blocklist.list()

    @app.post("/api/blocklist")
    def block(body: BlockRequest):
        try:
            ipaddress.ip_address(body.ip)
        except ValueError:
            raise HTTPException(422, "not a valid IP address") from None
        e = engine.blocklist.block(body.ip, body.reason, body.ttl)
        engine.bus.publish("blocklist", engine.blocklist.list())
        return e.to_dict()

    @app.delete("/api/blocklist/{ip}")
    def unblock(ip: str):
        if not engine.blocklist.unblock(ip):
            raise HTTPException(404, "not blocked")
        engine.bus.publish("blocklist", engine.blocklist.list())
        return {"unblocked": ip}

    # ------------------------------------------------------------ simulator control
    @app.get("/api/scenarios")
    def scenarios():
        from ..sources.simulator import SCENARIOS

        return {"enabled": engine.sim is not None, "scenarios": SCENARIOS,
                "campaigns": [c.to_dict() for c in engine.sim.campaigns] if engine.sim else []}

    @app.post("/api/scenarios/{name}")
    def launch(name: str):
        try:
            return engine.launch(name)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/topology")
    def topology():
        return engine.stats.topology()

    @app.get("/api/assets")
    def assets():
        return {"organization": engine.assets.organization, "hq": engine.assets.hq,
                "hosts": [a.to_dict() for a in engine.assets.by_ip.values()]}

    # ------------------------------------------------------------ live stream
    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        q = engine.bus.subscribe()
        try:
            await websocket.send_json({"type": "snapshot", "data": engine.snapshot()})
            while True:
                msg = await q.get()
                batch = [msg]
                while not q.empty() and len(batch) < 200:
                    batch.append(q.get_nowait())
                await websocket.send_json({"type": "batch", "data": batch})
        except (WebSocketDisconnect, asyncio.CancelledError, RuntimeError):
            pass
        finally:
            engine.bus.unsubscribe(q)
            with contextlib.suppress(Exception):
                await websocket.close()

    # ------------------------------------------------------------ dashboard
    if DIST.exists():
        app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            f = DIST / path
            if path and f.is_file():
                return FileResponse(f)
            return FileResponse(DIST / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        def root():
            return {"name": "ThreatPulse AI", "version": __version__,
                    "hint": "Build the dashboard: cd frontend && npm install && npm run build", "docs": "/docs"}

    return app
