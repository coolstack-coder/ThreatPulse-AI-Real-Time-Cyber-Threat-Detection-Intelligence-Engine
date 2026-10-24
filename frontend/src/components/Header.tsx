import type { Status } from "../types";
import { fmtBits, fmtNum } from "../format";

function Kpi({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className={`kpi ${tone ?? ""}`}>
      <div className="kpi-value">{value}</div>
      <div className="kpi-label">{label}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  );
}

export function Header({ status, connected, organization }: { status: Status | null; connected: boolean; organization: string }) {
  const s = status;
  const ml = !s ? "…" : s.ml_warmup > 0 ? `warming (${s.ml_warmup})` : `active · thr ${s.ml_threshold?.toFixed(3) ?? "-"}`;
  return (
    <header className="topbar">
      <div className="brand">
        <svg viewBox="0 0 32 32" className="logo" aria-hidden>
          <rect width="32" height="32" rx="8" fill="#0b1220" />
          <path d="M3 17h6l3-8 5 15 3-9 2 2h7" fill="none" stroke="#22d3ee" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div>
          <h1>
            ThreatPulse <span>AI</span>
          </h1>
          <div className="org">{organization || "Real-time threat detection"} · source: {s?.source ?? "-"}</div>
        </div>
        <span className={`live ${connected ? "on" : "off"}`}>
          <i /> {connected ? "LIVE" : "RECONNECTING"}
        </span>
      </div>
      <div className="kpis">
        <Kpi label="packets / s" value={s ? fmtNum(s.rates.packets) : "-"} hint={s ? `${fmtNum(s.packets)} total` : ""} />
        <Kpi label="throughput" value={s ? fmtBits(s.rates.bytes) : "-"} hint={s ? `${fmtNum(s.active_flows)} active flows` : ""} />
        <Kpi label="flows / s" value={s ? fmtNum(s.rates.flows) : "-"} hint={s ? `${fmtNum(s.flows)} total` : ""} />
        <Kpi label="alerts" value={s ? fmtNum(s.alerts) : "-"} tone={s && s.alerts ? "warn" : ""} />
        <Kpi label="open incidents" value={s ? String(s.open_incidents) : "-"} tone={s && s.open_incidents ? "danger" : ""} />
        <Kpi label="pipeline lag" value={s ? `${(s.pipeline_lag * 1000).toFixed(0)} ms` : "-"} hint={s ? `queue ${s.queue_depth}` : ""} />
        <Kpi label="HST anomaly model" value={ml} />
        <Kpi label="AI analyst" value={s?.llm ? "Grok online" : "template"} tone={s?.llm ? "ok" : ""} />
      </div>
    </header>
  );
}
