"""CVE zenginleştirme: CISA KEV (aktif sömürülüyor mu) + EPSS (sömürülme olasılığı)."""

from __future__ import annotations

import json
import time

import requests

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"

CACHE_DIR = config.BASE_DIR / ".cache" / "enrich"
_KEV_TTL = 24 * 3600

_kev_cache: set[str] | None = None


def get_kev_set() -> set[str]:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / "kev.json"

    data = None
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < _KEV_TTL:
        try:
            data = json.loads(cache_file.read_text())
        except json.JSONDecodeError:
            data = None

    if data is None:
        try:
            resp = requests.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            cache_file.write_text(json.dumps(data))
        except requests.RequestException:
            if cache_file.exists():
                data = json.loads(cache_file.read_text())
            else:
                return set()

    _kev_cache = {v.get("cveID", "").upper()
                  for v in data.get("vulnerabilities", []) if v.get("cveID")}
    return _kev_cache


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    ids = sorted({c.strip().upper() for c in cve_ids if c.strip()})
    scores: dict[str, float] = {}

    # EPSS API'sine 100'lük parçalar halinde sor
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cve = row.get("cve", "").upper()
                try:
                    scores[cve] = float(row.get("epss"))
                except (TypeError, ValueError):
                    pass
        except requests.RequestException:
            break

    return scores


def enrich(cve_ids: list[str]) -> tuple[set[str], dict[str, float]]:
    return get_kev_set(), get_epss_scores(cve_ids)


# --- CLI test ---
if __name__ == "__main__":
    kev = get_kev_set()
    print(f"KEV kataloğu: {len(kev)} aktif sömürülen CVE")
    test = ["CVE-2021-41773", "CVE-2017-3167", "CVE-2016-1908"]
    print("Örnekler KEV'de mi?:", {c: (c in kev) for c in test})
    print("EPSS skorları:", get_epss_scores(test))
