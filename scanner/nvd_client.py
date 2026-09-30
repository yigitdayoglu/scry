"""NVD API 2.0 istemcisi: rate limit + disk cache ile CVE/CVSS sorgular."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

import requests

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

CACHE_DIR = config.BASE_DIR / ".cache" / "nvd"


@dataclass
class CVEInfo:
    cve_id: str
    cvss_score: float | None
    severity: str
    description: str
    url: str

    def __str__(self) -> str:
        s = f"{self.cvss_score:.1f}" if self.cvss_score is not None else " -- "
        return f"[{self.severity:8}] {s}  {self.cve_id}  {self.description[:70]}"


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "BILINMIYOR"
    if score >= 9.0:
        return "KRITIK"
    if score >= 7.0:
        return "YUKSEK"
    if score >= 4.0:
        return "ORTA"
    if score > 0.0:
        return "DUSUK"
    return "BILINMIYOR"


def cpe22_to_23(cpe22: str) -> str | None:
    # cpe:/a:apache:http_server:2.4.7  ->  cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*
    if not cpe22 or not cpe22.startswith("cpe:/"):
        return None
    parts = cpe22[len("cpe:/"):].split(":")
    parts += ["*"] * (11 - len(parts))
    parts = parts[:11]
    return "cpe:2.3:" + ":".join(parts)


class NVDClient:

    def __init__(self, api_key: str | None = config.NVD_API_KEY,
                 use_cache: bool = True):
        self.api_key = api_key
        self.use_cache = use_cache

        # Anahtar varsa 50/30sn, yoksa 5/30sn
        self.min_interval = 0.7 if api_key else 6.5
        self._last_request = 0.0

        self.session = requests.Session()
        if api_key:
            self.session.headers["apiKey"] = api_key

        if use_cache:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # --- Arama ---

    def search_by_cpe(self, cpe22: str, max_results: int = 50) -> list[CVEInfo]:
        cpe23 = cpe22_to_23(cpe22)
        if not cpe23:
            return []
        return self._query({"virtualMatchString": cpe23}, max_results)

    def search_by_keyword(self, text: str, max_results: int = 50) -> list[CVEInfo]:
        text = text.strip()
        if not text:
            return []
        return self._query({"keywordSearch": text}, max_results)

    # --- İç mekanizma ---

    def _query(self, params: dict, max_results: int) -> list[CVEInfo]:
        params = {**params, "resultsPerPage": min(max_results, 2000)}
        cache_key = self._cache_key(params)

        cached = self._cache_read(cache_key)
        if cached is not None:
            return [self._to_cveinfo(v) for v in cached]

        self._respect_rate_limit()
        try:
            resp = self.session.get(config.NVD_API_BASE, params=params, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"[!] NVD isteği başarısız: {exc}")
            return []

        vulns = resp.json().get("vulnerabilities", [])
        simplified = [self._simplify(v) for v in vulns]
        self._cache_write(cache_key, simplified)
        return [self._to_cveinfo(v) for v in simplified]

    def _respect_rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()

    # --- JSON parse ---

    @staticmethod
    def _simplify(vuln: dict) -> dict:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        score, severity = NVDClient._best_cvss(cve.get("metrics", {}))
        return {
            "cve_id": cve_id,
            "cvss_score": score,
            "severity": severity,
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    @staticmethod
    def _best_cvss(metrics: dict) -> tuple[float | None, str]:
        # Tercih: v3.1 > v3.0 > v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                if score is not None:
                    return float(score), severity_from_score(float(score))
        return None, "BILINMIYOR"

    @staticmethod
    def _to_cveinfo(d: dict) -> CVEInfo:
        return CVEInfo(
            cve_id=d["cve_id"],
            cvss_score=d["cvss_score"],
            severity=d["severity"],
            description=d["description"],
            url=d["url"],
        )

    # --- Disk cache ---

    def _cache_key(self, params: dict) -> str:
        raw = json.dumps(params, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _cache_read(self, key: str):
        if not self.use_cache:
            return None
        f = CACHE_DIR / f"{key}.json"
        if f.exists():
            return json.loads(f.read_text())
        return None

    def _cache_write(self, key: str, data) -> None:
        if not self.use_cache:
            return
        (CACHE_DIR / f"{key}.json").write_text(json.dumps(data))


# --- CLI: python -m scanner.nvd_client cpe cpe:/a:apache:http_server:2.4.7 ---
if __name__ == "__main__":
    import sys

    client = NVDClient()
    mode = sys.argv[1] if len(sys.argv) > 1 else "cpe"
    query = sys.argv[2] if len(sys.argv) > 2 else "cpe:/a:apache:http_server:2.4.7"

    print(f"[*] NVD sorgusu ({mode}): {query}")
    if mode == "cpe":
        results = client.search_by_cpe(query, max_results=20)
    else:
        results = client.search_by_keyword(query, max_results=20)

    print(f"[+] {len(results)} CVE bulundu:\n")
    for cve in sorted(results, key=lambda c: c.cvss_score or -1, reverse=True):
        print("   ", cve)
