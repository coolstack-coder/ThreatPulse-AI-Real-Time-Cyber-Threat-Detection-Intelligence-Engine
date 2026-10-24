"""Prometheus metrics. Exposed at ``/metrics`` and scraped by the bundled Prometheus."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

PACKETS = Counter("threatpulse_packets_total", "Packets processed", registry=REGISTRY)
BYTES = Counter("threatpulse_bytes_total", "Bytes processed", registry=REGISTRY)
FLOWS = Counter("threatpulse_flows_total", "Flows completed", registry=REGISTRY)
DROPPED = Counter("threatpulse_dropped_packets_total", "Packets dropped before detection",
                  ["reason"], registry=REGISTRY)
ALERTS = Counter("threatpulse_alerts_total", "Alerts raised", ["detector", "severity"], registry=REGISTRY)
INCIDENTS = Counter("threatpulse_incidents_total", "Incidents opened", ["severity"], registry=REGISTRY)
ACTIVE_FLOWS = Gauge("threatpulse_active_flows", "Flows currently tracked", registry=REGISTRY)
OPEN_INCIDENTS = Gauge("threatpulse_open_incidents", "Incidents not yet resolved", registry=REGISTRY)
QUEUE_DEPTH = Gauge("threatpulse_ingest_queue_depth", "Packets waiting in the ingest queue", registry=REGISTRY)
WS_CLIENTS = Gauge("threatpulse_ws_clients", "Connected dashboard clients", registry=REGISTRY)
BATCH_LATENCY = Histogram(
    "threatpulse_batch_processing_seconds", "Wall time to run one ingest batch through detection",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0), registry=REGISTRY,
)
PIPELINE_LAG = Gauge("threatpulse_pipeline_lag_seconds",
                     "Wall-clock delay between capture and detection for the newest packet", registry=REGISTRY)
LLM_CALLS = Counter("threatpulse_llm_calls_total", "LLM narrative requests", ["outcome"], registry=REGISTRY)
