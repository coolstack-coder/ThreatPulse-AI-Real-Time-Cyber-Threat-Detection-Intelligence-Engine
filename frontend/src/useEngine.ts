import { useEffect, useReducer, useRef } from "react";
import type { Alert, BlockEntry, Campaign, GeoEvent, Incident, Snapshot, Status, Topology } from "./types";

export interface EngineState {
  connected: boolean;
  status: Status | null;
  alerts: Alert[];
  incidents: Record<string, Incident>;
  topology: Topology;
  geoEvents: GeoEvent[];
  scenarios: Record<string, string>;
  campaigns: Campaign[];
  blocklist: BlockEntry[];
  hq: Snapshot["hq"] | null;
  organization: string;
}

type Msg = { type: string; data: any };
type Action = { kind: "open" } | { kind: "close" } | { kind: "msgs"; msgs: Msg[] };

const initial: EngineState = {
  connected: false,
  status: null,
  alerts: [],
  incidents: {},
  topology: { nodes: [], edges: [] },
  geoEvents: [],
  scenarios: {},
  campaigns: [],
  blocklist: [],
  hq: null,
  organization: "",
};

const MAX_ALERTS = 250;

function apply(state: EngineState, msg: Msg): EngineState {
  switch (msg.type) {
    case "snapshot": {
      const s = msg.data as Snapshot;
      const incidents: Record<string, Incident> = {};
      for (const i of s.incidents) incidents[i.id] = i;
      return {
        ...state,
        status: s.status,
        alerts: [...s.alerts].reverse(),
        incidents,
        topology: s.topology,
        geoEvents: s.geo_events,
        scenarios: s.scenarios,
        campaigns: s.campaigns,
        blocklist: s.blocklist,
        hq: s.hq,
        organization: s.organization,
      };
    }
    case "stats":
      return { ...state, status: msg.data };
    case "alert": {
      const a = msg.data as Alert;
      const geo = a.enrichment?.attacker_geo || a.enrichment?.peer_geo;
      const geoEvents =
        geo && state.hq && a.severity !== "low"
          ? [...state.geoEvents.slice(-80), { ts: a.ts, ip: a.attacker || a.peers[0], type: a.type, severity: a.severity, geo, hq: state.hq }]
          : state.geoEvents;
      return { ...state, alerts: [a, ...state.alerts].slice(0, MAX_ALERTS), geoEvents };
    }
    case "incident": {
      const inc = msg.data as Incident;
      return { ...state, incidents: { ...state.incidents, [inc.id]: inc } };
    }
    case "topology":
      return { ...state, topology: msg.data };
    case "campaign":
      return { ...state, campaigns: [...state.campaigns.slice(-19), msg.data] };
    case "blocklist":
      return { ...state, blocklist: msg.data };
    default:
      return state;
  }
}

function reducer(state: EngineState, action: Action): EngineState {
  if (action.kind === "open") return { ...state, connected: true };
  if (action.kind === "close") return { ...state, connected: false };
  return action.msgs.reduce(apply, state);
}

/** Holds a WebSocket to the engine and folds the event stream into dashboard state. */
export function useEngine(): EngineState {
  const [state, dispatch] = useReducer(reducer, initial);
  const retry = useRef(0);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: number | undefined;
    let stopped = false;

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => {
        retry.current = 0;
        dispatch({ kind: "open" });
      };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data) as Msg;
        dispatch({ kind: "msgs", msgs: msg.type === "batch" ? msg.data : [msg] });
      };
      ws.onclose = () => {
        dispatch({ kind: "close" });
        if (stopped) return;
        const delay = Math.min(8000, 500 * 2 ** retry.current++);
        timer = window.setTimeout(connect, delay);
      };
    };
    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return state;
}

export const api = {
  launch: (name: string) => fetch(`/api/scenarios/${name}`, { method: "POST" }).then((r) => r.json()),
  block: (ip: string, reason: string) =>
    fetch(`/api/blocklist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason }),
    }).then((r) => r.json()),
  unblock: (ip: string) => fetch(`/api/blocklist/${ip}`, { method: "DELETE" }).then((r) => r.json()),
  setStatus: (id: string, status: string) =>
    fetch(`/api/incidents/${id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    }).then((r) => r.json()),
  incident: (id: string) => fetch(`/api/incidents/${id}`).then((r) => r.json()),
  assets: () => fetch(`/api/assets`).then((r) => r.json()),
};
