export type Severity = "low" | "medium" | "high" | "critical";

export interface Geo {
  country: string;
  city: string;
  lat: number;
  lon: number;
  org?: string;
}

export interface Alert {
  id: string;
  ts: number;
  detector: string;
  type: string;
  title: string;
  severity: Severity;
  score: number;
  attacker: string | null;
  victim: string | null;
  peers: string[];
  description: string;
  evidence: Record<string, unknown>;
  tactic: string;
  technique: string;
  technique_name: string;
  incident_id: string | null;
  enrichment: {
    attacker_geo?: Geo | null;
    peer_geo?: Geo | null;
    attacker_asset?: Asset | null;
    victim_asset?: Asset | null;
  };
}

export interface Asset {
  ip: string;
  name: string;
  role: string;
  criticality: number;
  public?: boolean;
}

export interface TimelineEntry {
  ts: number;
  alert_id: string;
  type: string;
  title: string;
  severity: Severity;
  tactic: string;
  technique: string;
}

export interface Incident {
  id: string;
  title: string;
  status: "open" | "acknowledged" | "resolved";
  severity: Severity;
  risk: number;
  first_seen: number;
  last_seen: number;
  attackers: string[];
  victims: string[];
  compromised: string[];
  tactics: string[];
  techniques: Record<string, string>;
  alert_count: number;
  alert_types: Record<string, number>;
  timeline: TimelineEntry[];
  summary: string;
  summary_source: "llm" | "template" | "";
  recommendations: string[];
  enrichment: {
    attackers?: { ip: string; geo: Geo | null }[];
    targets?: Asset[];
    kill_chain_progress?: number;
  };
}

export interface SeriesPoint {
  t: number;
  packets: number;
  bytes: number;
  flows: number;
  alerts: number;
  dropped: number;
}

export interface Status {
  version: string;
  source: string;
  uptime: number;
  packets: number;
  bytes: number;
  flows: number;
  active_flows: number;
  alerts: number;
  incidents: number;
  open_incidents: number;
  threat_level: number;
  queue_depth: number;
  pipeline_lag: number;
  blocked: number;
  llm: boolean;
  ml_threshold: number | null;
  ml_warmup: number;
  detectors: Record<string, number>;
  series: SeriesPoint[];
  rates: { packets: number; bytes: number; flows: number; alerts: number };
  top_talkers: { ip: string; bytes: number }[];
  protocols: Record<string, number>;
  severity: Record<string, number>;
  by_detector: Record<string, number>;
}

export interface TopoNode {
  id: string;
  internal: boolean;
  flagged: boolean;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface TopoEdge {
  source: string | TopoNode;
  target: string | TopoNode;
  bytes: number;
  flagged: Severity | null;
}

export interface Topology {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

export interface GeoEvent {
  ts: number;
  ip: string;
  type: string;
  severity: Severity;
  geo: Geo;
  hq: { lat: number; lon: number; city: string };
}

export interface Campaign {
  id: string;
  scenario: string;
  start: number;
  end: number;
  actors: string[];
  victims: string[];
  description: string;
}

export interface BlockEntry {
  ip: string;
  reason: string;
  created: number;
  expires: number | null;
  by: string;
  dropped: number;
  commands: string[];
}

export interface Snapshot {
  status: Status;
  alerts: Alert[];
  incidents: Incident[];
  topology: Topology;
  geo_events: GeoEvent[];
  scenarios: Record<string, string>;
  campaigns: Campaign[];
  blocklist: BlockEntry[];
  hq: { city: string; country: string; lat: number; lon: number };
  organization: string;
}
