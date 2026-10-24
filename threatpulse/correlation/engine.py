"""Alert correlation: turns a stream of alerts into kill-chain incidents.

Alerts are linked through shared *entities*, using union-find semantics:

* the external attacker IP (or attacker infrastructure: C2 servers, exfil endpoints, bad domains),
* internal hosts that are *compromised*, meaning a successful login landed on them or they
  have started generating high-severity malicious traffic themselves.

This is how a scan and a brute force from an external IP join up with the beaconing,
lateral movement and exfiltration that the victim host produces later: the victim becomes
a pivot. Victims of failed attacks are *not* pivots, so one busy server being attacked by
two unrelated actors does not merge two stories into one.

Low-confidence alerts (ML anomalies, volume spikes) can enrich an existing incident but
never open one alone. That keeps analyst-facing noise low.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable

from ..config import CorrelationConfig
from ..intel.assets import AssetInventory
from ..intel.geo import GeoResolver
from ..models import Alert, Incident, Severity
from ..netutil import is_internal
from .mitre import KILL_CHAIN, stage_index, technique_for

SUPPORTING_ONLY = {"flow_anomaly", "volume_anomaly"}
COMPROMISE_SIGNALS = {"beaconing", "dns_tunnel", "lateral_movement", "exfiltration", "ioc_match", "port_scan"}


class Correlator:
    def __init__(self, cfg: CorrelationConfig | None = None, assets: AssetInventory | None = None,
                 geo: GeoResolver | None = None):
        self.cfg = cfg or CorrelationConfig()
        self.assets = assets or AssetInventory()
        self.geo = geo or GeoResolver()
        self.incidents: dict[str, Incident] = {}
        self._index: dict[str, str] = {}  # entity -> incident id
        self._ids = itertools.count(1)
        self.listeners: list[Callable[[Incident, bool], None]] = []
        self.orphans = 0

    # ------------------------------------------------------------------ public API
    def ingest(self, alert: Alert) -> Incident | None:
        keys = self._link_keys(alert)
        matches: list[Incident] = []
        for k in keys:
            iid = self._index.get(k)
            inc = self.incidents.get(iid) if iid else None
            if inc and inc.status != "resolved" and alert.ts - inc.last_seen <= self.cfg.window and inc not in matches:
                matches.append(inc)

        created = False
        if matches:
            inc = max(matches, key=lambda i: len(i.alert_ids))
            for other in matches:
                if other is not inc:
                    self._merge(inc, other)
        else:
            if alert.type in SUPPORTING_ONLY or alert.severity < self.cfg.min_new_incident_severity:
                self.orphans += 1
                return None
            inc = Incident(id=f"INC-{next(self._ids):04d}", first_seen=alert.ts, last_seen=alert.ts)
            self.incidents[inc.id] = inc
            created = True

        self._attach(inc, alert)
        for cb in self.listeners:
            cb(inc, created)
        return inc

    def set_status(self, incident_id: str, status: str) -> Incident | None:
        inc = self.incidents.get(incident_id)
        if inc and status in {"open", "acknowledged", "resolved"}:
            inc.status = status
            for cb in self.listeners:
                cb(inc, False)
        return inc

    def open_incidents(self) -> list[Incident]:
        return [i for i in self.incidents.values() if i.status != "resolved"]

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _link_keys(a: Alert) -> list[str]:
        keys = []
        if a.attacker:
            keys.append(a.attacker)
        keys.extend(p for p in a.peers if not is_internal(p))
        return keys

    def _attach(self, inc: Incident, a: Alert) -> None:
        a.incident_id = inc.id
        inc.alert_ids.append(a.id)
        inc.alert_types[a.type] = inc.alert_types.get(a.type, 0) + 1
        inc.first_seen = min(inc.first_seen, a.ts)
        inc.last_seen = max(inc.last_seen, a.ts)
        inc.campaigns |= a.campaigns

        new_entities: list[str] = []
        if a.attacker:
            if is_internal(a.attacker):
                if a.type in COMPROMISE_SIGNALS and a.severity >= Severity.MEDIUM:
                    inc.compromised.add(a.attacker)
                    new_entities.append(a.attacker)
            else:
                inc.attackers.add(a.attacker)
                new_entities.append(a.attacker)
        for p in a.peers:
            if not is_internal(p):
                if a.type not in SUPPORTING_ONLY:
                    inc.attackers.add(p)
                    new_entities.append(p)
            elif a.type == "lateral_movement":
                inc.victims.add(p)
        if a.victim:
            inc.victims.add(a.victim)
            if a.type == "brute_force_success":
                inc.compromised.add(a.victim)
                new_entities.append(a.victim)
        for e in new_entities:
            self._index[e] = inc.id

        tech = technique_for(a.type)
        if tech.tactic not in inc.tactics:
            inc.tactics.append(tech.tactic)
            inc.tactics.sort(key=stage_index)
        inc.techniques[tech.id] = tech.name
        inc.timeline.append({
            "ts": a.ts, "alert_id": a.id, "type": a.type, "title": a.title, "severity": a.severity.label,
            "tactic": tech.tactic, "technique": tech.id,
        })
        if len(inc.timeline) > 200:
            inc.timeline = inc.timeline[-200:]
        self._rescore(inc, a)

    def _merge(self, keep: Incident, gone: Incident) -> None:
        keep.alert_ids.extend(gone.alert_ids)
        for t, n in gone.alert_types.items():
            keep.alert_types[t] = keep.alert_types.get(t, 0) + n
        keep.first_seen = min(keep.first_seen, gone.first_seen)
        keep.last_seen = max(keep.last_seen, gone.last_seen)
        keep.attackers |= gone.attackers
        keep.victims |= gone.victims
        keep.compromised |= gone.compromised
        keep.campaigns |= gone.campaigns
        for t in gone.tactics:
            if t not in keep.tactics:
                keep.tactics.append(t)
        keep.tactics.sort(key=stage_index)
        keep.techniques.update(gone.techniques)
        keep.timeline = sorted(keep.timeline + gone.timeline, key=lambda e: e["ts"])[-200:]
        keep.enrichment.setdefault("merged_from", []).append(gone.id)
        keep.risk = max(keep.risk, gone.risk)
        for e, iid in list(self._index.items()):
            if iid == gone.id:
                self._index[e] = keep.id
        gone.status = "resolved"
        gone.enrichment["merged_into"] = keep.id
        del self.incidents[gone.id]

    def _rescore(self, inc: Incident, latest: Alert) -> None:
        sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        peak = max((sev_rank[e["severity"]] for e in inc.timeline), default=1)
        base = max(latest.score, inc.enrichment.get("peak_score", 0.0))
        inc.enrichment["peak_score"] = base
        stages = {t for t in inc.tactics}
        progression = max((stage_index(t) for t in stages), default=0)
        crit = max([self.assets.criticality(h) for h in inc.victims | inc.compromised] or [2])
        bonus = 6 * (len(stages) - 1) + 1.5 * progression + (8 if inc.compromised else 0)
        risk = (base + bonus) * (1 + 0.06 * (crit - 2))
        inc.risk = round(min(100.0, max(risk, inc.risk)), 1)
        inc.severity = max(Severity.from_score(inc.risk), Severity(min(peak, 4)))

        # Title: the furthest kill-chain stage reached, plus the main target
        target_ip = next(iter(sorted(inc.compromised)), None) or next(iter(sorted(inc.victims)), None)
        target = self.assets.name(target_ip) if target_ip else ", ".join(sorted(inc.attackers)[:2])
        if len(stages) >= 3:
            inc.title = f"Multi-stage intrusion: {len(stages)} ATT&CK tactics on {target}"
        else:
            top = max(inc.timeline, key=lambda e: (sev_rank[e["severity"]], e["ts"]))
            inc.title = top["title"]

        recs, seen = [], set()
        for t in sorted(inc.alert_types, key=lambda t: -stage_index(technique_for(t).tactic)):
            pb = technique_for(t).playbook
            if pb not in seen:
                seen.add(pb)
                recs.append(pb)
        inc.recommendations = recs[:6]

        inc.enrichment["attackers"] = [
            {"ip": ip, "geo": self.geo.lookup(ip)} for ip in sorted(inc.attackers)[:8]
        ]
        inc.enrichment["targets"] = [self.assets.describe(ip) for ip in sorted(inc.victims | inc.compromised)[:12]]
        inc.enrichment["kill_chain_progress"] = round((progression + 1) / len(KILL_CHAIN), 2)
        if not inc.summary or inc.summary_source != "llm":
            inc.summary = template_summary(inc, self.assets)
            inc.summary_source = "template"


def template_summary(inc: Incident, assets: AssetInventory) -> str:
    """A deterministic analyst-style narrative, used when no LLM is configured."""
    ext = [e for e in inc.enrichment.get("attackers", []) if e.get("geo")]
    origin = ""
    if ext:
        g = ext[0]["geo"]
        origin = f" originating from {g['city']}, {g['country']}"
    actors = ", ".join(sorted(inc.attackers)[:3]) or "an internal host"
    steps = []
    seen = set()
    for e in inc.timeline:
        if e["type"] in seen:
            continue
        seen.add(e["type"])
        steps.append(f"{e['tactic'].lower()} ({e['technique']}: {e['title']})")
    comp = ", ".join(assets.name(h) for h in sorted(inc.compromised)) or "none confirmed"
    chain = "; then ".join(steps[:6])
    return (
        f"{inc.severity.label.upper()} incident{origin}. Activity from {actors} progressed through "
        f"{len(inc.tactics)} ATT&CK tactic(s): {chain}. Compromised hosts: {comp}. "
        f"Risk {inc.risk:.0f}/100 across {len(inc.alert_ids)} correlated alert(s). "
        f"Priority action: {inc.recommendations[0] if inc.recommendations else 'investigate.'}"
    )
