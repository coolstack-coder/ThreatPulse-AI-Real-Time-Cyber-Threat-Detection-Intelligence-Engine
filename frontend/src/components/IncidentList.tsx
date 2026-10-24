import type { Incident } from "../types";
import { KILL_CHAIN, SEV_COLOR, SEV_RANK, ago } from "../format";
import { SevBadge } from "./Panel";

export function KillChainStrip({ tactics }: { tactics: string[] }) {
  return (
    <div className="kc-strip" title={tactics.join(" → ")}>
      {KILL_CHAIN.map((t) => (
        <i key={t} className={tactics.includes(t) ? "on" : ""} />
      ))}
    </div>
  );
}

/** Incidents ranked by status, then severity, then recency. */
export function IncidentList({ incidents, onOpen }: { incidents: Incident[]; onOpen: (id: string) => void }) {
  const rows = [...incidents]
    .sort(
      (a, b) =>
        Number(a.status === "resolved") - Number(b.status === "resolved") ||
        SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
        b.last_seen - a.last_seen,
    )
    .slice(0, 30);
  if (!rows.length) return <div className="empty">No incidents. Correlated attacks will show up here.</div>;
  return (
    <ul className="incidents">
      {rows.map((i) => (
        <li key={i.id} onClick={() => onOpen(i.id)} className={`incident ${i.status}`} style={{ borderLeftColor: SEV_COLOR[i.severity] }}>
          <div className="incident-top">
            <span className="mono id">{i.id}</span>
            <SevBadge severity={i.severity} />
            <span className="risk mono">risk {Math.round(i.risk)}</span>
            {i.status !== "open" && <span className="status">{i.status}</span>}
            <span className="muted right">{ago(i.last_seen)}</span>
          </div>
          <div className="incident-title">{i.title}</div>
          <div className="incident-bottom">
            <KillChainStrip tactics={i.tactics} />
            <span className="muted">
              {i.alert_count} alerts · {i.tactics.length} tactics
              {i.compromised.length > 0 && <b className="comp"> · {i.compromised.length} compromised</b>}
            </span>
          </div>
        </li>
      ))}
    </ul>
  );
}
