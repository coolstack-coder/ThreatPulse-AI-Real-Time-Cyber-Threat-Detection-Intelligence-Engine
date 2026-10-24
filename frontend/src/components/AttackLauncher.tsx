import { useState } from "react";
import type { Campaign } from "../types";
import { api } from "../useEngine";
import { nowTs } from "../format";

const ICON: Record<string, string> = {
  apt_killchain: "☠",
  port_scan: "⌖",
  brute_force: "🔑",
  syn_flood: "🌊",
  beaconing: "📡",
  dns_tunnel: "🕳",
  lateral_movement: "⇄",
  exfiltration: "⇪",
  ioc_contact: "☣",
};

/** Red-team console: launches simulated attack campaigns and tracks the ones in progress. */
export function AttackLauncher({ scenarios, campaigns }: { scenarios: Record<string, string>; campaigns: Campaign[] }) {
  const [busy, setBusy] = useState<string | null>(null);
  const now = nowTs();
  const active = campaigns.filter((c) => c.end > now - 5).slice(-3);
  const names = Object.keys(scenarios);
  if (!names.length) return <div className="muted pad">Attack simulation is only available with the simulator source.</div>;
  const ordered = ["apt_killchain", ...names.filter((n) => n !== "apt_killchain")];

  return (
    <div className="launcher">
      <div className="launch-grid">
        {ordered.map((n) => (
          <button
            key={n}
            className={`launch ${n === "apt_killchain" ? "launch-apt" : ""}`}
            title={scenarios[n]}
            disabled={busy === n}
            onClick={async () => {
              setBusy(n);
              try {
                await api.launch(n);
              } finally {
                setTimeout(() => setBusy(null), 800);
              }
            }}
          >
            <span className="launch-icon">{ICON[n] ?? "!"}</span>
            {n === "apt_killchain" ? "Full kill chain" : n.replace(/_/g, " ")}
          </button>
        ))}
      </div>
      <div className="campaigns">
        {active.length === 0 && <span className="muted">No active campaigns</span>}
        {active.map((c) => {
          const pct = Math.min(100, Math.max(0, ((now - c.start) / Math.max(1, c.end - c.start)) * 100));
          return (
            <div key={c.id} className="campaign">
              <div className="campaign-row">
                <span className="mono">{c.id}</span>
                <span className="muted">{pct >= 100 ? "complete" : `${Math.round(pct)}%`}</span>
              </div>
              <div className="bar">
                <div style={{ width: `${pct}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
