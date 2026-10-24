# Problem Analysis — Why ThreatPulse AI Exists

> This document is the research step I did before writing any code. It covers the problem,
> who has it, how it gets solved today, where those solutions fall short, and what this
> project has to do to be worth building.

## 1. The problem

Breaches are found too late, and the time an attacker spends inside a network is
what drives the damage.

| Metric (IBM *Cost of a Data Breach 2025*) | Value |
|---|---|
| Mean time to **identify** a breach | **181 days** |
| Mean time to **contain** it | 60 days |
| Global average breach cost | $4.44M (US: $10.2M) |
| Savings when the org detects it itself (vs. the attacker disclosing it) | ~$0.9M |
| Savings from heavy use of security AI and automation | ~$1.9M, plus a breach lifecycle ~80 days shorter |

Most intrusions leave **network evidence** long before the payoff. Recon scans, credential
spraying, command-and-control beacons, lateral movement and staged exfiltration all
generate traffic. The evidence is there. It goes unnoticed for three reasons:

1. **Volume.** One mid-size network produces millions of flows per hour, and nobody reads them.
2. **Fragmentation.** Every stage of an attack looks harmless on its own. A single
   SMB connection is normal, and a DNS query with a long subdomain is *usually* normal. The signal is in the
   **sequence** (recon → access → C2 → lateral movement → exfiltration).
3. **Alert fatigue.** Rule-based IDSs fire thousands of uncorrelated alerts, so analysts
   start ignoring them, and real incidents get buried.

## 2. How it is solved today

| Approach | Examples | Strength | Weakness |
|---|---|---|---|
| Signature NIDS | Snort, Suricata | Precise on known threats, fast | Blind to new attacks; every match is a separate alert |
| Network metadata analysers | Zeek, RITA | Rich protocol logs, beacon hunting | Batch/hunt oriented; needs an analyst to drive it |
| SIEM correlation | Splunk ES, Elastic, Sentinel | Cross-source correlation | Expensive, heavy, rules written by hand, high latency |
| Commercial NDR with ML | Darktrace, Vectra, ExtraHop | Behavioural detection | Black box, very expensive, not something you can learn from |
| Academic ML IDS | CICIDS2017 / UNSW-NB15 models | High offline accuracy | Batch-trained on fixed datasets; models drift and break on live traffic |

**The gap:** there is no small, *transparent*, end-to-end, **streaming** system that runs
signature rules, behavioural statistics and online ML side by side, then **correlates** the
results into kill-chain incidents an analyst can act on, all observable in real time.

## 3. What ThreatPulse AI must do (requirements)

### Functional
- **F1 Ingest** packets from live capture (scapy), PCAP replay, or a realistic **labelled
  traffic simulator**. The simulator lets the system be demoed and *measured* without
  touching a real network.
- **F2 Assemble flows** with bidirectional 5-tuple tracking, idle and active timeouts, and
  CICFlowMeter-style features (bytes, packets, durations, flag counts, inter-arrival stats).
- **F3 Detect** with layered detectors:
  - *Stateful rules:* port scan, SYN flood, brute force, lateral movement, exfiltration.
  - *Behavioural statistics:* C2 beacon periodicity (coefficient of variation of
    inter-arrival times, plus destination rarity) and DNS tunnelling (label entropy,
    length, unique-subdomain rate).
  - *Online ML:* **Streaming Half-Space Trees** (Tan, Ting & Liu, IJCAI 2011). They train
    on normal traffic only, use constant memory, and adapt as traffic drifts. A per-host
    EWMA volume baseline sits alongside them.
  - *Threat intelligence:* IOC matching on IPs and domains.
- **F4 Correlate** alerts into **incidents** by linking entities over time, map them to
  **MITRE ATT&CK** tactics and techniques, track kill-chain progression, and compute a risk
  score that accounts for asset criticality.
- **F5 Enrich and explain:** asset inventory, GeoIP, recommended response actions, and an
  analyst-style incident narrative (Grok LLM when a key is configured, with a deterministic
  template fallback).
- **F6 Respond:** a block list (SOAR-lite) whose blocked IPs are dropped at ingest. This
  closes the detect → respond loop.
- **F7 Visualise live:** a SOC dashboard with an attack map, throughput, alert stream,
  incidents with ATT&CK timelines, a network graph, and an on-demand attack launcher.

### Non-functional
- **Event-time processing.** Detectors use packet timestamps, not wall-clock time, so
  replaying a PCAP gives the same results as live traffic and tests are deterministic.
- **Bounded memory.** Sliding windows, LRU flow tables and constant-memory ML.
- **Backpressure and observability.** Bounded queues, a drop counter, Prometheus metrics
  for throughput and pipeline latency, and health endpoints.
- **Measurable.** Because the simulator labels its own traffic, the system reports
  **per-scenario recall, false-positive rate and detection latency (MTTD)** and does not
  just claim to work.

## 4. Threat scenarios modelled

| Scenario | Network evidence | ATT&CK |
|---|---|---|
| Port scan | One source hits many destination ports, mostly unanswered SYNs | T1046 Network Service Discovery |
| SSH/RDP brute force | Many short, small flows to 22/3389 | T1110 Brute Force |
| SYN flood | High SYN rate with a low SYN-ACK ratio | T1498 Network DoS |
| C2 beaconing | Regular intervals (low CV) to a rare external host | T1071.001 Web Protocols C2 |
| DNS tunnelling | High-entropy, long, unique subdomains under one domain | T1071.004 DNS C2 / T1048 |
| Lateral movement | Internal host fans out over SMB/RDP/WinRM | T1021 Remote Services |
| Data exfiltration | Outbound bytes far above baseline to a rare destination | T1041 / T1048 |
| Known-bad contact | Destination on an IOC feed | T1071 (intel match) |
| **Full kill chain (APT)** | All of the above, in sequence | Multi-tactic incident |

## 5. Design decisions

| Decision | Choice | Why |
|---|---|---|
| Language | Python 3.11+ (asyncio) | Mature security tooling (scapy), numpy for ML, FastAPI for streaming APIs |
| Bus | In-process async pub/sub with bounded queues | Zero-dependency demo; the interface maps directly onto Kafka/Redis Streams |
| ML | Half-Space Trees written from scratch in numpy | Streaming, unsupervised and constant memory, and the code shows how it actually works |
| Time | Event time with watermark-driven flow expiry | Deterministic replays and tests |
| Storage | SQLite (WAL) | Durable alerts and incidents with no extra infrastructure; easy to swap for Postgres |
| UI | React + Vite + d3, served by FastAPI over WebSocket | Live push, a single deployable artifact |
| Metrics | Prometheus | Standard for production observability |

## 6. Success criteria
- ≥ 95% recall across the simulated attack scenarios, with median detection latency under 10 s
  of event time.
- Fewer than 1 false-positive incident per simulated hour of benign traffic.
- The full kill chain merges into **one** incident covering at least 4 ATT&CK tactics.
- Throughput of ≥ 20k packets/s on a laptop in replay mode.

## References
- Tan, Ting, Liu, *Fast Anomaly Detection for Streaming Data*, IJCAI 2011.
- IBM Security, *Cost of a Data Breach Report 2025*.
- Sharafaldin et al., *CICIDS2017*, ICISSP 2018 (flow feature set).
- MITRE ATT&CK® Enterprise Matrix.
- Active Countermeasures, RITA (beacon scoring ideas).
