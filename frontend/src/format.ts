import type { Severity } from "./types";

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff3b5c",
  high: "#ff8a3d",
  medium: "#fbbf24",
  low: "#60a5fa",
};

export const SEV_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export const KILL_CHAIN = [
  "Reconnaissance",
  "Discovery",
  "Credential Access",
  "Initial Access",
  "Command and Control",
  "Lateral Movement",
  "Exfiltration",
  "Impact",
];

export const TYPE_LABEL: Record<string, string> = {
  port_scan: "Port scan",
  syn_flood: "SYN flood",
  brute_force: "Brute force",
  brute_force_success: "Login after brute force",
  lateral_movement: "Lateral movement",
  exfiltration: "Exfiltration",
  beaconing: "C2 beaconing",
  dns_tunnel: "DNS tunnelling",
  ioc_match: "Threat intel match",
  flow_anomaly: "ML anomaly",
  volume_anomaly: "Volume spike",
};

export function fmtNum(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + "B";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(1) + "k";
  return Math.round(n).toLocaleString();
}

export function fmtBytes(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
  return n + " B";
}

export function fmtBits(bytesPerSec: number): string {
  const b = bytesPerSec * 8;
  if (b >= 1e9) return (b / 1e9).toFixed(2) + " Gbps";
  if (b >= 1e6) return (b / 1e6).toFixed(1) + " Mbps";
  return (b / 1e3).toFixed(0) + " Kbps";
}

export function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

// The engine runs on event time (a replay or a sped-up simulation can be ahead of or behind
// the wall clock), so relative times are measured against the engine's clock.
let clockOffset = 0;
export function syncClock(eventTime: number) {
  clockOffset = eventTime - Date.now() / 1000;
}
export function nowTs(): number {
  return Date.now() / 1000 + clockOffset;
}

export function ago(ts: number): string {
  const s = Math.max(0, nowTs() - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export function flag(country?: string): string {
  const codes: Record<string, string> = {
    "United States": "US", Russia: "RU", Germany: "DE", China: "CN", Vietnam: "VN", Brazil: "BR",
    "South Africa": "ZA", Netherlands: "NL", Romania: "RO", India: "IN", "United Kingdom": "GB",
    Japan: "JP", Singapore: "SG", Ireland: "IE",
  };
  const c = country && codes[country];
  if (!c) return "🌐";
  return String.fromCodePoint(...[...c].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}
