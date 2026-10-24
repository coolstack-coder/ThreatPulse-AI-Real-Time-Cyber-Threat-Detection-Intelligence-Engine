import type { Status } from "../types";
import { SEV_COLOR } from "../format";

function level(v: number) {
  if (v >= 85) return { label: "CRITICAL", color: SEV_COLOR.critical };
  if (v >= 65) return { label: "HIGH", color: SEV_COLOR.high };
  if (v >= 40) return { label: "ELEVATED", color: SEV_COLOR.medium };
  if (v > 0) return { label: "GUARDED", color: SEV_COLOR.low };
  return { label: "NORMAL", color: "#34d399" };
}

/** Semicircular gauge of the highest open-incident risk, plus severity counts. */
export function ThreatGauge({ status }: { status: Status | null }) {
  const v = status?.threat_level ?? 0;
  const lv = level(v);
  const r = 70;
  const cx = 90;
  const cy = 84;
  const angle = Math.PI * (1 - v / 100);
  const end = [cx + r * Math.cos(angle), cy - r * Math.sin(angle)];
  const large = 0;
  const sev = status?.severity ?? {};
  return (
    <div className="gauge">
      <svg viewBox="0 0 180 100" className="gauge-svg">
        <path d={`M${cx - r},${cy} A${r},${r} 0 0 1 ${cx + r},${cy}`} className="gauge-track" />
        {v > 0 && (
          <path
            d={`M${cx - r},${cy} A${r},${r} 0 ${large} 1 ${end[0]},${end[1]}`}
            stroke={lv.color}
            className="gauge-fill"
          />
        )}
        <text x={cx} y={cy - 18} className="gauge-value" fill={lv.color}>
          {Math.round(v)}
        </text>
        <text x={cx} y={cy - 2} className="gauge-label">
          {lv.label}
        </text>
      </svg>
      <div className="sev-grid">
        {(["critical", "high", "medium", "low"] as const).map((k) => (
          <div key={k} className="sev-cell">
            <b style={{ color: SEV_COLOR[k] }}>{sev[k] ?? 0}</b>
            <span>{k}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
