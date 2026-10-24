"""LLM incident narratives (xAI Grok, through its OpenAI-compatible API).

This is optional. Without ``XAI_API_KEY`` (or ``GROK_API_KEY``) the engine keeps the
deterministic template narrative. The LLM only *explains* an incident that the detectors and
correlator already found; it never decides whether something is an attack.
"""

from __future__ import annotations

import json
import logging
import time

import httpx

from ..config import LLMConfig
from ..models import Incident

log = logging.getLogger("threatpulse.llm")

SYSTEM_PROMPT = (
    "You are a senior SOC analyst. Given a correlated network-security incident as JSON, write a "
    "concise briefing for an on-call engineer: 3-5 sentences covering what happened in kill-chain "
    "order, the likely attacker objective, the blast radius, and the single most urgent containment "
    "step. Be factual: only use the evidence provided. No markdown headings."
)


class IncidentNarrator:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._client: httpx.AsyncClient | None = None
        self._last_call: dict[str, float] = {}
        self._fingerprint: dict[str, str] = {}
        self.calls = 0
        self.failures = 0

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.enabled and self.cfg.api_key)

    def should_narrate(self, inc: Incident, min_severity: int) -> bool:
        if not self.enabled or inc.severity < min_severity:
            return False
        fp = f"{len(inc.tactics)}|{sorted(inc.alert_types)}|{inc.severity}"
        if self._fingerprint.get(inc.id) == fp:
            return False  # nothing materially new since the last narrative
        if time.monotonic() - self._last_call.get(inc.id, 0.0) < 15:
            return False
        return True

    async def narrate(self, inc: Incident) -> str | None:
        self._last_call[inc.id] = time.monotonic()
        self._fingerprint[inc.id] = f"{len(inc.tactics)}|{sorted(inc.alert_types)}|{inc.severity}"
        payload = {
            "id": inc.id, "severity": inc.severity.label, "risk": inc.risk, "title": inc.title,
            "attackers": inc.enrichment.get("attackers"), "targets": inc.enrichment.get("targets"),
            "compromised_hosts": sorted(inc.compromised), "tactics": inc.tactics, "techniques": inc.techniques,
            "timeline": [{k: e[k] for k in ("type", "title", "tactic", "technique", "severity")}
                         for e in inc.timeline[-25:]],
        }
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.cfg.base_url, timeout=self.cfg.timeout)
        try:
            self.calls += 1
            r = await self._client.post(
                "/chat/completions",
                headers={"Authorization": f"Bearer {self.cfg.api_key}"},
                json={
                    "model": self.cfg.model,
                    "temperature": 0.2,
                    "max_tokens": 400,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(payload, default=str)},
                    ],
                },
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"].strip()
            return text or None
        except Exception as exc:  # network, auth, quota... fall back to the template
            self.failures += 1
            log.warning("LLM narrative failed for %s: %s", inc.id, exc)
            return None

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
