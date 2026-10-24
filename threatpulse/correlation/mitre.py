"""MITRE ATT&CK mapping and kill-chain ordering for every alert type."""

from __future__ import annotations

from dataclasses import dataclass

# Tactics in rough kill-chain order. Incidents are scored by how far along this list they get.
KILL_CHAIN = [
    "Reconnaissance",
    "Discovery",
    "Credential Access",
    "Initial Access",
    "Command and Control",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
]


@dataclass(frozen=True)
class Technique:
    tactic: str
    id: str
    name: str
    playbook: str


TECHNIQUES: dict[str, Technique] = {
    "port_scan": Technique(
        "Discovery", "T1046", "Network Service Discovery",
        "Block the scanning source at the perimeter and review which services are exposed.",
    ),
    "brute_force": Technique(
        "Credential Access", "T1110", "Brute Force",
        "Rate-limit or geo-block the source, enforce MFA and lockout on the targeted service.",
    ),
    "brute_force_success": Technique(
        "Initial Access", "T1078", "Valid Accounts",
        "Treat the target as compromised: reset its credentials, isolate the host and review session logs.",
    ),
    "syn_flood": Technique(
        "Impact", "T1498", "Network Denial of Service",
        "Enable SYN cookies and upstream scrubbing, and rate-limit at the edge.",
    ),
    "beaconing": Technique(
        "Command and Control", "T1071.001", "Application Layer Protocol: Web",
        "Isolate the beaconing host, block the C2 destination, and capture memory for forensics.",
    ),
    "dns_tunnel": Technique(
        "Command and Control", "T1071.004", "Application Layer Protocol: DNS",
        "Sinkhole the tunnelling domain and force all DNS through a filtering resolver.",
    ),
    "lateral_movement": Technique(
        "Lateral Movement", "T1021", "Remote Services",
        "Segment the source host, disable SMB/RDP between workstations, and audit admin credentials.",
    ),
    "exfiltration": Technique(
        "Exfiltration", "T1041", "Exfiltration Over C2 Channel",
        "Block the destination, preserve the flow records, and start a data-loss assessment.",
    ),
    "volume_anomaly": Technique(
        "Exfiltration", "T1048", "Exfiltration Over Alternative Protocol",
        "Check the host's outbound transfers against its business baseline.",
    ),
    "ioc_match": Technique(
        "Command and Control", "T1071", "Application Layer Protocol",
        "Block the known-bad indicator and hunt for other hosts that contacted it.",
    ),
    "flow_anomaly": Technique(
        "Discovery", "T1046", "Anomalous Network Behaviour",
        "Review the flagged flows; ML anomalies are leads to investigate, not verdicts.",
    ),
}


def technique_for(alert_type: str) -> Technique:
    return TECHNIQUES.get(alert_type, Technique("Discovery", "T0000", "Unknown", "Investigate."))


def stage_index(tactic: str) -> int:
    try:
        return KILL_CHAIN.index(tactic)
    except ValueError:
        return 0
