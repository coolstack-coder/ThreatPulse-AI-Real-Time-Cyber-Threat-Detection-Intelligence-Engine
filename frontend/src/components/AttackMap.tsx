import { useMemo } from "react";
import { geoGraticule10, geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import type { GeometryCollection, Topology as TopoJSON } from "topojson-specification";
import type { GeoEvent } from "../types";
import { SEV_COLOR, TYPE_LABEL, flag, nowTs } from "../format";
import { useSize } from "../useSize";

const topo = world as unknown as TopoJSON<{ countries: GeometryCollection }>;
const countries = feature(topo, topo.objects.countries);

/** Live attack map: arcs from each attacker's location to HQ (or from HQ out to C2/exfil endpoints). */
export function AttackMap({ events, hq }: { events: GeoEvent[]; hq: { lat: number; lon: number; city: string } | null }) {
  const [ref, { width, height }] = useSize<HTMLDivElement>();
  const now = nowTs();

  const { path, projection, graticule } = useMemo(() => {
    const projection = geoNaturalEarth1().fitExtent(
      [[6, 6], [Math.max(10, width - 6), Math.max(10, height - 6)]],
      { type: "Sphere" },
    );
    return { path: geoPath(projection), projection, graticule: geoGraticule10() };
  }, [width, height]);

  // Newest event per source IP, from the last 10 minutes
  const recent = useMemo(() => {
    const byIp = new Map<string, GeoEvent>();
    for (const e of events) if (now - e.ts < 600) byIp.set(`${e.ip}|${e.type}`, e);
    return [...byIp.values()].slice(-25);
  }, [events, Math.floor(now / 5)]);

  const hqPt = hq ? projection([hq.lon, hq.lat]) : null;
  const outbound = new Set(["beaconing", "exfiltration", "ioc_match", "dns_tunnel"]);

  return (
    <div className="map" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height}>
          <defs>
            <radialGradient id="hqglow">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
            </radialGradient>
          </defs>
          <path d={path({ type: "Sphere" }) ?? ""} className="sphere" />
          <path d={path(graticule) ?? ""} className="graticule" />
          {countries.features.map((f, i) => (
            <path key={i} d={path(f) ?? ""} className="country" />
          ))}
          {hqPt &&
            recent.map((e) => {
              const src = projection([e.geo.lon, e.geo.lat]);
              if (!src) return null;
              const out = outbound.has(e.type);
              const [a, b] = out ? [hqPt, src] : [src, hqPt];
              const mx = (a[0] + b[0]) / 2;
              const my = (a[1] + b[1]) / 2 - Math.hypot(b[0] - a[0], b[1] - a[1]) * 0.28;
              const fresh = now - e.ts < 30;
              const color = SEV_COLOR[e.severity];
              return (
                <g key={`${e.ip}-${e.type}`} opacity={fresh ? 1 : 0.45}>
                  <path d={`M${a[0]},${a[1]} Q${mx},${my} ${b[0]},${b[1]}`} stroke={color} className={`arc ${fresh ? "fresh" : ""}`} />
                  <circle cx={src[0]} cy={src[1]} r={fresh ? 4.5 : 3} fill={color} className={fresh ? "ping" : ""} />
                  <title>{`${flag(e.geo.country)} ${e.ip} · ${e.geo.city}, ${e.geo.country}\n${TYPE_LABEL[e.type] ?? e.type} (${e.severity})`}</title>
                </g>
              );
            })}
          {hqPt && (
            <g>
              <circle cx={hqPt[0]} cy={hqPt[1]} r={22} fill="url(#hqglow)" className="hq-pulse" />
              <circle cx={hqPt[0]} cy={hqPt[1]} r={4.5} fill="#22d3ee" stroke="#fff" strokeWidth={1.2} />
              <text x={hqPt[0] + 9} y={hqPt[1] + 4} className="hq-label">
                HQ · {hq?.city}
              </text>
            </g>
          )}
        </svg>
      )}
      <div className="map-legend">
        {recent.length === 0 ? (
          <span className="muted">No geolocated threats yet. Launch a scenario →</span>
        ) : (
          recent
            .slice(-4)
            .reverse()
            .map((e) => (
              <span key={`${e.ip}${e.type}`} className="legend-item">
                <i style={{ background: SEV_COLOR[e.severity] }} />
                {flag(e.geo.country)} {e.geo.city} · {TYPE_LABEL[e.type] ?? e.type}
              </span>
            ))
        )}
      </div>
    </div>
  );
}
