import { TYPE_LABEL } from "../format";

const LAYER: Record<string, { layer: string; color: string }> = {
  port_scan: { layer: "rule", color: "#22d3ee" },
  syn_flood: { layer: "rule", color: "#22d3ee" },
  brute_force: { layer: "rule", color: "#22d3ee" },
  brute_force_success: { layer: "rule", color: "#22d3ee" },
  lateral_movement: { layer: "rule", color: "#22d3ee" },
  exfiltration: { layer: "rule", color: "#22d3ee" },
  beaconing: { layer: "behaviour", color: "#a78bfa" },
  dns_tunnel: { layer: "behaviour", color: "#a78bfa" },
  ioc_match: { layer: "intel", color: "#f472b6" },
  flow_anomaly: { layer: "ML", color: "#34d399" },
  volume_anomaly: { layer: "ML", color: "#34d399" },
};

/** Alerts per detection type, coloured by detection layer (rules, behaviour, intel, ML). */
export function DetectorBars({ byDetector }: { byDetector: Record<string, number> }) {
  const rows = Object.keys(LAYER)
    .map((k) => ({ k, n: byDetector[k] ?? 0 }))
    .sort((a, b) => b.n - a.n);
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <div className="bars">
      {rows.map(({ k, n }) => (
        <div key={k} className="bar-row">
          <span className="bar-label">{TYPE_LABEL[k] ?? k}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(n / max) * 100}%`, background: LAYER[k].color }} />
          </div>
          <span className="bar-n mono">{n}</span>
        </div>
      ))}
      <div className="layer-legend">
        {[
          ["rules", "#22d3ee"],
          ["behaviour", "#a78bfa"],
          ["threat intel", "#f472b6"],
          ["online ML", "#34d399"],
        ].map(([l, c]) => (
          <span key={l}>
            <i style={{ background: c }} />
            {l}
          </span>
        ))}
      </div>
    </div>
  );
}
