import { useEffect, useRef, useState } from "react";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type Simulation } from "d3-force";
import type { Asset, TopoEdge, TopoNode, Topology } from "../types";
import { SEV_COLOR } from "../format";
import { useSize } from "../useSize";

/** Force-directed graph of who talks to whom (last 60s), with attack paths highlighted. */
export function NetworkGraph({ topology, assets }: { topology: Topology; assets: Record<string, Asset> }) {
  const [ref, { width, height }] = useSize<HTMLDivElement>();
  const sim = useRef<Simulation<TopoNode, TopoEdge> | null>(null);
  const nodesRef = useRef<Map<string, TopoNode>>(new Map());
  const [, setTick] = useState(0);
  const [edges, setEdges] = useState<TopoEdge[]>([]);

  useEffect(() => {
    if (!width || !height) return;
    const prev = nodesRef.current;
    const next = new Map<string, TopoNode>();
    for (const n of topology.nodes) {
      const old = prev.get(n.id);
      next.set(n.id, old ? Object.assign(old, { flagged: n.flagged }) : { ...n, x: width / 2 + (Math.random() - 0.5) * 80, y: height / 2 + (Math.random() - 0.5) * 80 });
    }
    nodesRef.current = next;
    const links: TopoEdge[] = topology.edges
      .filter((e) => next.has(e.source as string) && next.has(e.target as string))
      .map((e) => ({ ...e }));
    setEdges(links);

    sim.current?.stop();
    const maxB = Math.max(1, ...links.map((l) => l.bytes));
    sim.current = forceSimulation<TopoNode>([...next.values()])
      .force("link", forceLink<TopoNode, TopoEdge>(links).id((d) => d.id).distance((l) => (l.flagged ? 70 : 40 + 30 * (1 - l.bytes / maxB))).strength(0.5))
      .force("charge", forceManyBody().strength(-60))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide(9))
      .alpha(prev.size ? 0.35 : 1)
      .on("tick", () => {
        for (const n of next.values()) {
          n.x = Math.max(10, Math.min(width - 10, n.x ?? 0));
          n.y = Math.max(10, Math.min(height - 10, n.y ?? 0));
        }
        setTick((t) => t + 1);
      });
    return () => {
      sim.current?.stop();
    };
  }, [topology, width, height]);

  const nodes = [...nodesRef.current.values()];
  const label = (id: string) => assets[id]?.name ?? (id.startsWith("10.") ? id : "");
  const important = (n: TopoNode) => n.flagged || (assets[n.id] && assets[n.id].role !== "workstation");

  return (
    <div className="graph" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height}>
          {edges.map((e, i) => {
            const s = e.source as TopoNode;
            const t = e.target as TopoNode;
            if (s.x == null || t.x == null) return null;
            return (
              <line
                key={i}
                x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                className={e.flagged ? "edge flagged" : "edge"}
                stroke={e.flagged ? SEV_COLOR[e.flagged] : undefined}
              />
            );
          })}
          {nodes.map((n) => (
            <g key={n.id} transform={`translate(${n.x},${n.y})`}>
              <circle
                r={n.flagged ? 7 : assets[n.id] && assets[n.id].role !== "workstation" ? 6 : 4}
                className={`node ${n.internal ? "internal" : "external"} ${n.flagged ? "flagged" : ""}`}
              />
              {important(n) && (
                <text x={9} y={3} className={`node-label ${n.flagged ? "flagged" : ""}`}>
                  {label(n.id) || n.id}
                </text>
              )}
              <title>{`${assets[n.id]?.name ?? ""} ${n.id}${n.flagged ? " · involved in an alert" : ""}`}</title>
            </g>
          ))}
        </svg>
      )}
      <div className="graph-legend">
        <span><i className="dot internal" />internal</span>
        <span><i className="dot external" />external</span>
        <span><i className="dot flagged" />attack path</span>
      </div>
    </div>
  );
}
