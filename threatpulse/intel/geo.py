"""IP geolocation.

Uses a MaxMind GeoLite2 City database when ``THREATPULSE_GEOIP_DB`` points to one and the
``geoip2`` package is installed. Otherwise it falls back to a small built-in prefix table
covering the address ranges the simulator uses, so the attack map works offline.
"""

from __future__ import annotations

import os

from ..netutil import is_internal

# prefix -> (country, city, lat, lon, org). Illustrative values for the demo only.
DEMO_GEO: dict[str, tuple[str, str, float, float, str]] = {
    "142.250.": ("United States", "Mountain View", 37.39, -122.08, "Google"),
    "13.107.": ("United States", "Redmond", 47.67, -122.12, "Microsoft"),
    "151.101.": ("United States", "San Francisco", 37.77, -122.42, "Fastly CDN"),
    "104.16.": ("United States", "San Francisco", 37.78, -122.40, "Cloudflare"),
    "52.95.": ("United States", "Seattle", 47.61, -122.33, "Amazon AWS"),
    "157.240.": ("Ireland", "Dublin", 53.35, -6.26, "Meta"),
    "140.82.": ("United States", "Ashburn", 39.04, -77.49, "GitHub"),
    "20.190.": ("Netherlands", "Amsterdam", 52.37, 4.90, "Microsoft Azure"),
    "45.155.205.": ("Russia", "Moscow", 55.76, 37.62, "Hosting (demo)"),
    "185.220.101.": ("Germany", "Frankfurt", 50.11, 8.68, "Tor exit (demo)"),
    "91.240.118.": ("Russia", "Saint Petersburg", 59.93, 30.36, "Bulletproof hosting (demo)"),
    "61.177.172.": ("China", "Nanjing", 32.06, 118.80, "ISP (demo)"),
    "103.75.": ("Vietnam", "Hanoi", 21.03, 105.85, "VPS (demo)"),
    "177.54.": ("Brazil", "São Paulo", -23.55, -46.63, "ISP (demo)"),
    "196.251.": ("South Africa", "Johannesburg", -26.20, 28.05, "VPS (demo)"),
    "5.188.206.": ("Netherlands", "Amsterdam", 52.37, 4.90, "Hosting (demo)"),
    "212.102.": ("Romania", "Bucharest", 44.43, 26.10, "VPS (demo)"),
    "49.36.": ("India", "Mumbai", 19.08, 72.88, "Reliance Jio"),
    "106.51.": ("India", "Bengaluru", 12.97, 77.59, "ACT Fibernet"),
    "81.2.": ("United Kingdom", "London", 51.51, -0.13, "ISP"),
    "118.27.": ("Japan", "Tokyo", 35.68, 139.69, "ISP"),
    "1.32.": ("Singapore", "Singapore", 1.35, 103.82, "ISP"),
}


class GeoResolver:
    def __init__(self, mmdb_path: str | None = None):
        self._reader = None
        self._cache: dict[str, dict | None] = {}
        path = mmdb_path or os.getenv("THREATPULSE_GEOIP_DB")
        if path and os.path.exists(path):
            try:
                import geoip2.database  # type: ignore

                self._reader = geoip2.database.Reader(path)
            except Exception:  # pragma: no cover - optional dependency
                self._reader = None

    def lookup(self, ip: str | None) -> dict | None:
        if not ip or is_internal(ip) or "→" in ip:
            return None
        if ip in self._cache:
            return self._cache[ip]
        if len(self._cache) > 50_000:
            self._cache.clear()
        res = self._cache[ip] = self._resolve(ip)
        return res

    def _resolve(self, ip: str) -> dict | None:
        if self._reader is not None:  # pragma: no cover - needs a real database
            try:
                r = self._reader.city(ip)
                return {"country": r.country.name, "city": r.city.name, "lat": r.location.latitude,
                        "lon": r.location.longitude, "org": ""}
            except Exception:
                pass
        for prefix, (country, city, lat, lon, org) in DEMO_GEO.items():
            if ip.startswith(prefix):
                return {"country": country, "city": city, "lat": lat, "lon": lon, "org": org}
        return None
