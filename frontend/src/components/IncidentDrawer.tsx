import type { BlockEntry, Incident } from "../types";
import { KILL_CHAIN, SEV_COLOR, TYPE_LABEL, flag, fmtTime } from "../format";
import { api } from "../useEngine";
import { SevBadge } from "./Panel";

/** Incident detail: kill-chain progress, AI narrative, entities, timeline and response actions. */
export function IncidentDrawer({ incident, blocklist, onClose }: { incident: Incident | null; blocklist: BlockEntry[]; onClose: () => void }) {
  if (!incident) return null;
  const i = incident;
  const blocked = new Set(blocklist.map((b) => b.ip));
  const blockable = i.attackers.filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a));
  const reached = Math.max(-1, ...i.tactics.map((t) => KILL_CHAIN.indexOf(t)));

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <header className="drawer-head" style={{ borderTopColor: SEV_COLOR[i.severity] }}>
          <div className="drawer-meta">
            <span className="mono">{i.id}</span>
            <SevBadge severity={i.severity} />
            <span className="mono risk">risk {Math.round(i.risk)}/100</span>
            <span className="status">{i.status}</span>
            <button className="close" onClick={onClose} aria-label="close">✕</button>
          </div>
          <h3>{i.title}</h3>
          <div className="muted">
            {fmtTime(i.first_seen)} → {fmtTime(i.last_seen)} · {i.alert_count} correlated alerts
          </div>
        </header>

        <section>
          <h4>Kill chain</h4>
          <div className="kc">
            {KILL_CHAIN.map((t, idx) => (
              <div key={t} className={`kc-step ${i.tactics.includes(t) ? "hit" : idx <= reached ? "passed" : ""}`}>
                <i />
                <span>{t}</span>
              </div>
            ))}
          </div>
          <div className="techniques">
            {Object.entries(i.techniques).map(([id, name]) => (
              <span key={id} className="tech-chip">
                <b>{id}</b> {name}
              </span>
            ))}
          </div>
        </section>

        <section>
          <h4>
            Analyst briefing <span className={`src ${i.summary_source}`}>{i.summary_source === "llm" ? "Grok" : "auto-generated"}</span>
          </h4>
          <p className="summary">{i.summary}</p>
        </section>

        <section className="entities">
          <div>
            <h4>Attacker infrastructure</h4>
            {i.enrichment.attackers?.map((a) => (
              <div key={a.ip} className="entity">
                <span>{flag(a.geo?.country)}</span>
                <span className="mono">{a.ip}</span>
                <span className="muted">{a.geo ? `${a.geo.city}, ${a.geo.country} · ${a.geo.org ?? ""}` : "spoofed / unknown"}</span>
              </div>
            ))}
            {!i.enrichment.attackers?.length && <div className="muted">Internal origin</div>}
          </div>
          <div>
            <h4>Affected assets</h4>
            {i.enrichment.targets?.map((t) => (
              <div key={t.ip} className="entity">
                <span className={`crit c${t.criticality}`}>{t.criticality}</span>
                <span className="mono">{t.name}</span>
                <span className="muted">{t.ip} · {t.role}</span>
                {i.compromised.includes(t.ip) && <b className="comp">COMPROMISED</b>}
              </div>
            ))}
          </div>
        </section>

        <section>
          <h4>Response</h4>
          <ol className="recs">
            {i.recommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ol>
          <div className="actions">
            {blockable.map((ip) => (
              <button key={ip} className="danger" disabled={blocked.has(ip)} onClick={() => api.block(ip, `${i.id}: ${i.title}`)}>
                {blocked.has(ip) ? `✓ ${ip} blocked` : `Block ${ip}`}
              </button>
            ))}
            {i.status === "open" && <button onClick={() => api.setStatus(i.id, "acknowledged")}>Acknowledge</button>}
            {i.status !== "resolved" && <button onClick={() => api.setStatus(i.id, "resolved")}>Resolve</button>}
          </div>
        </section>

        <section>
          <h4>Timeline</h4>
          <ul className="timeline">
            {[...i.timeline].reverse().map((e) => (
              <li key={e.alert_id}>
                <i style={{ background: SEV_COLOR[e.severity] }} />
                <span className="mono t">{fmtTime(e.ts)}</span>
                <span className="tl-tactic">{e.tactic}</span>
                <span>{TYPE_LABEL[e.type] ?? e.type}</span>
                <span className="muted tl-title">{e.title}</span>
              </li>
            ))}
          </ul>
        </section>
      </aside>
    </div>
  );
}
