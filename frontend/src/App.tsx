import { useEffect, useMemo, useState } from "react";
import type { Asset } from "./types";
import { api, useEngine } from "./useEngine";
import { Header } from "./components/Header";
import { Panel } from "./components/Panel";
import { AttackMap } from "./components/AttackMap";
import { TrafficChart } from "./components/TrafficChart";
import { ThreatGauge } from "./components/ThreatGauge";
import { AttackLauncher } from "./components/AttackLauncher";
import { DetectorBars } from "./components/DetectorBars";
import { IncidentList } from "./components/IncidentList";
import { AlertFeed } from "./components/AlertFeed";
import { NetworkGraph } from "./components/NetworkGraph";
import { Blocklist, TopTalkers } from "./components/TopTalkers";
import { IncidentDrawer } from "./components/IncidentDrawer";

export default function App() {
  const st = useEngine();
  const [openId, setOpenId] = useState<string | null>(null);
  const [assets, setAssets] = useState<Record<string, Asset>>({});

  useEffect(() => {
    api.assets().then((d: { hosts: Asset[] }) => setAssets(Object.fromEntries(d.hosts.map((h) => [h.ip, h]))));
  }, []);

  // Re-render every second so relative times and campaign progress keep moving
  const [, setNow] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setNow((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const incidents = useMemo(() => Object.values(st.incidents), [st.incidents]);
  const openIncidents = incidents.filter((i) => i.status !== "resolved").length;

  return (
    <div className="app">
      <Header status={st.status} connected={st.connected} organization={st.organization} />
      <main className="grid">
        <Panel title="Live attack map" className="span-8 h-map" right={<span className="muted">attacker → HQ · HQ → C2</span>}>
          <AttackMap events={st.geoEvents} hq={st.hq} />
        </Panel>
        <div className="span-4 stack">
          <Panel title="Threat level">
            <ThreatGauge status={st.status} />
          </Panel>
          <Panel title="Red-team console" right={<span className="muted">simulated attacks</span>}>
            <AttackLauncher scenarios={st.scenarios} campaigns={st.campaigns} />
          </Panel>
        </div>

        <Panel title="Network traffic" className="span-8 h-chart" right={<span className="muted">last 2 min · event time</span>}>
          <TrafficChart series={st.status?.series ?? []} />
        </Panel>
        <Panel title="Detections by type" className="span-4 h-chart">
          <DetectorBars byDetector={st.status?.by_detector ?? {}} />
        </Panel>

        <Panel title="Incidents" className="span-5 h-feed" right={<span className="pill">{openIncidents} open</span>}>
          <IncidentList incidents={incidents} onOpen={setOpenId} />
        </Panel>
        <Panel title="Live alert stream" className="span-7 h-feed" right={<span className="muted">{st.alerts.length} recent</span>}>
          <AlertFeed alerts={st.alerts} onOpenIncident={setOpenId} />
        </Panel>

        <Panel title="Network graph" className="span-7 h-graph" right={<span className="muted">flows, last 60s</span>}>
          <NetworkGraph topology={st.topology} assets={assets} />
        </Panel>
        <div className="span-5 stack">
          <Panel title="Top talkers" right={<span className="muted">bytes, last 60s</span>}>
            <TopTalkers talkers={st.status?.top_talkers ?? []} assets={assets} />
          </Panel>
          <Panel title="Active blocks" right={<span className="muted">enforced at ingest</span>}>
            <Blocklist entries={st.blocklist} />
          </Panel>
        </div>
      </main>
      <footer className="foot">
        ThreatPulse AI v{st.status?.version ?? "1.0.0"} · streaming flow analytics · Half-Space-Trees online ML · MITRE ATT&CK correlation ·{" "}
        <a href="/docs" target="_blank" rel="noreferrer">API</a> · <a href="/metrics" target="_blank" rel="noreferrer">metrics</a>
      </footer>
      <IncidentDrawer incident={openId ? st.incidents[openId] ?? null : null} blocklist={st.blocklist} onClose={() => setOpenId(null)} />
    </div>
  );
}
