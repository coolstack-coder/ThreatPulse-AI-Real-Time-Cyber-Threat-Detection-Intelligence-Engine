import type { SeriesPoint } from "../types";
import { fmtBits, fmtNum } from "../format";
import { useSize } from "../useSize";

/** Packets/s area, throughput line, and red markers on seconds that raised alerts. */
export function TrafficChart({ series }: { series: SeriesPoint[] }) {
  const [ref, { width, height }] = useSize<HTMLDivElement>();
  const data = series.slice(-120);
  const pad = { l: 44, r: 54, t: 10, b: 22 };
  const w = Math.max(0, width - pad.l - pad.r);
  const h = Math.max(0, height - pad.t - pad.b);
  const maxP = Math.max(10, ...data.map((d) => d.packets)) * 1.15;
  const maxB = Math.max(1000, ...data.map((d) => d.bytes)) * 1.15;
  const x = (i: number) => pad.l + (data.length <= 1 ? 0 : (i / (data.length - 1)) * w);
  const yP = (v: number) => pad.t + h - (v / maxP) * h;
  const yB = (v: number) => pad.t + h - (v / maxB) * h;

  const area =
    data.length > 1
      ? `M${x(0)},${pad.t + h} ` + data.map((d, i) => `L${x(i)},${yP(d.packets)}`).join(" ") + ` L${x(data.length - 1)},${pad.t + h} Z`
      : "";
  const line = data.map((d, i) => `${i ? "L" : "M"}${x(i)},${yB(d.bytes)}`).join(" ");
  const ticks = [0, 0.5, 1];

  return (
    <div className="chart" ref={ref}>
      {width > 0 && data.length > 1 && (
        <svg width={width} height={height}>
          <defs>
            <linearGradient id="pk" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={pad.l + w} y1={pad.t + h * (1 - t)} y2={pad.t + h * (1 - t)} className="grid" />
              <text x={pad.l - 6} y={pad.t + h * (1 - t) + 4} className="axis" textAnchor="end">
                {fmtNum(maxP * t)}
              </text>
              <text x={pad.l + w + 6} y={pad.t + h * (1 - t) + 4} className="axis axis-b">
                {fmtBits(maxB * t)}
              </text>
            </g>
          ))}
          <path d={area} fill="url(#pk)" stroke="#22d3ee" strokeWidth={1.6} />
          <path d={line} fill="none" stroke="#a78bfa" strokeWidth={1.4} strokeDasharray="4 3" />
          {data.map((d, i) =>
            d.alerts > 0 ? (
              <g key={d.t}>
                <line x1={x(i)} x2={x(i)} y1={pad.t} y2={pad.t + h} stroke="#ff3b5c" strokeOpacity={0.35} />
                <circle cx={x(i)} cy={pad.t + 4} r={3.5} fill="#ff3b5c" />
              </g>
            ) : null,
          )}
          <text x={pad.l} y={height - 5} className="axis">
            −{data.length}s
          </text>
          <text x={pad.l + w} y={height - 5} className="axis" textAnchor="end">
            now
          </text>
        </svg>
      )}
      <div className="chart-legend">
        <span><i style={{ background: "#22d3ee" }} />packets/s</span>
        <span><i style={{ background: "#a78bfa" }} />throughput</span>
        <span><i style={{ background: "#ff3b5c" }} />alert</span>
      </div>
    </div>
  );
}
