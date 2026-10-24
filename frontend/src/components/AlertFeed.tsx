import { useState } from "react";
import type { Alert } from "../types";
import { TYPE_LABEL, flag, fmtTime } from "../format";
import { SevBadge } from "./Panel";

/** Streaming alert table with a severity filter and expandable evidence. */
export function AlertFeed({ alerts, onOpenIncident }: { alerts: Alert[]; onOpenIncident: (id: string) => void }) {
  const [minSev, setMinSev] = useState<"all" | "medium" | "high">("all");
  const [open, setOpen] = useState<string | null>(null);
  const rank = { low: 1, medium: 2, high: 3, critical: 4 } as const;
  const floor = minSev === "all" ? 0 : rank[minSev];
  const rows = alerts.filter((a) => rank[a.severity] >= floor).slice(0, 80);

  return (
    <div className="feed">
      <div className="feed-filter">
        {(["all", "medium", "high"] as const).map((k) => (
          <button key={k} className={minSev === k ? "active" : ""} onClick={() => setMinSev(k)}>
            {k === "all" ? "all" : `${k}+`}
          </button>
        ))}
      </div>
      <div className="feed-scroll">
        {rows.length === 0 && <div className="empty">Watching traffic… no alerts yet.</div>}
        {rows.map((a) => {
          const geo = a.enrichment?.attacker_geo;
          return (
            <div key={a.id} className={`alert-row ${open === a.id ? "open" : ""}`} onClick={() => setOpen(open === a.id ? null : a.id)}>
              <div className="alert-main">
                <span className="mono t">{fmtTime(a.ts)}</span>
                <SevBadge severity={a.severity} />
                <span className="atype">{TYPE_LABEL[a.type] ?? a.type}</span>
                <span className="atitle">{a.title}</span>
                <span className="mono tech">{a.technique}</span>
                {geo && <span className="geo">{flag(geo.country)}</span>}
              </div>
              {open === a.id && (
                <div className="alert-detail">
                  <p>{a.description}</p>
                  <div className="kv">
                    <span>detector</span><b>{a.detector}</b>
                    <span>ATT&CK</span><b>{a.technique} · {a.technique_name} ({a.tactic})</b>
                    {a.attacker && (<><span>attacker</span><b className="mono">{a.attacker}{geo ? ` · ${geo.city}, ${geo.country}` : ""}</b></>)}
                    {a.victim && (<><span>target</span><b className="mono">{a.enrichment?.victim_asset?.name ?? a.victim} ({a.victim})</b></>)}
                    <span>score</span><b>{a.score}</b>
                  </div>
                  <pre className="evidence">{JSON.stringify(a.evidence, null, 1)}</pre>
                  {a.incident_id && (
                    <button className="link" onClick={(e) => { e.stopPropagation(); onOpenIncident(a.incident_id!); }}>
                      open {a.incident_id} →
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
