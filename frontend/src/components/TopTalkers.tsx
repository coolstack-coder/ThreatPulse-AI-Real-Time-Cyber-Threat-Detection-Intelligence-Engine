import type { Asset, BlockEntry } from "../types";
import { ago, fmtBytes, fmtNum } from "../format";
import { api } from "../useEngine";

export function TopTalkers({ talkers, assets }: { talkers: { ip: string; bytes: number }[]; assets: Record<string, Asset> }) {
  const max = Math.max(1, ...talkers.map((t) => t.bytes));
  return (
    <div className="talkers">
      {talkers.map((t) => (
        <div key={t.ip} className="talker">
          <span className="mono ip">{t.ip}</span>
          <span className="tname">{assets[t.ip]?.name ?? ""}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(t.bytes / max) * 100}%` }} />
          </div>
          <span className="mono">{fmtBytes(t.bytes)}</span>
        </div>
      ))}
      {!talkers.length && <div className="empty">Collecting…</div>}
    </div>
  );
}

export function Blocklist({ entries }: { entries: BlockEntry[] }) {
  if (!entries.length) return <div className="empty small">No active blocks. Block an attacker from an incident.</div>;
  return (
    <div className="blocklist">
      {entries.map((e) => (
        <div key={e.ip} className="block-row">
          <span className="mono ip">{e.ip}</span>
          <span className="muted">{e.reason}</span>
          <span className="mono drops">{fmtNum(e.dropped)} dropped</span>
          <span className="muted">{ago(e.created)}</span>
          <button className="ghost" onClick={() => api.unblock(e.ip)}>unblock</button>
        </div>
      ))}
    </div>
  );
}
