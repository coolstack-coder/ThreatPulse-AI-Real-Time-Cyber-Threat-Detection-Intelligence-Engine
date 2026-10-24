"""Asset inventory: what an internal IP is and how much it matters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..netutil import is_internal


@dataclass(frozen=True)
class Asset:
    ip: str
    name: str
    role: str
    criticality: int = 2
    public: bool = False

    def to_dict(self) -> dict:
        return {"ip": self.ip, "name": self.name, "role": self.role,
                "criticality": self.criticality, "public": self.public}


class AssetInventory:
    def __init__(self, assets: list[Asset] | None = None, organization: str = "",
                 hq: dict | None = None, admin_hosts: set[str] | None = None):
        self.by_ip = {a.ip: a for a in assets or []}
        self.organization = organization
        self.hq = hq or {"city": "HQ", "country": "", "lat": 12.97, "lon": 77.59}
        self.admin_hosts = admin_hosts or set()

    @classmethod
    def load(cls, path: str | Path) -> AssetInventory:
        p = Path(path)
        if not p.exists():
            return cls()
        data = yaml.safe_load(p.read_text()) or {}
        assets = [Asset(ip=str(h["ip"]), name=h["name"], role=h.get("role", "server"),
                        criticality=int(h.get("criticality", 3)), public=bool(h.get("public", False)))
                  for h in data.get("hosts", [])]
        ws = data.get("workstations")
        if ws:
            for i in range(int(ws["count"])):
                assets.append(Asset(ip=f"{ws['prefix']}{int(ws['start']) + i}", name=f"ws-{i + 1:02d}",
                                    role="workstation", criticality=int(ws.get("criticality", 2))))
        return cls(assets, data.get("organization", ""), data.get("hq"),
                   {str(x) for x in data.get("admin_hosts", [])})

    def get(self, ip: str) -> Asset | None:
        return self.by_ip.get(ip)

    def describe(self, ip: str) -> dict:
        a = self.by_ip.get(ip)
        if a:
            return a.to_dict()
        return {"ip": ip, "name": ip, "role": "internal" if is_internal(ip) else "external", "criticality": 2}

    def name(self, ip: str) -> str:
        a = self.by_ip.get(ip)
        return f"{a.name} ({ip})" if a else ip

    def criticality(self, ip: str | None) -> int:
        if not ip:
            return 2
        a = self.by_ip.get(ip)
        return a.criticality if a else 2

    def by_role(self, role: str) -> list[Asset]:
        return [a for a in self.by_ip.values() if a.role == role]
