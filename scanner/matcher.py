"""ServiceInfo -> CVE eşleştirme (CPE inşası + NVD sorgusu)."""

from __future__ import annotations

import re

try:
    import config  # noqa: F401
except ModuleNotFoundError:
    from .. import config  # type: ignore

from .nmap_scanner import ServiceInfo
from .nvd_client import NVDClient, CVEInfo

# nmap 'product' adında geçen alt-dize -> NVD (vendor, product). Genişletilebilir.
PRODUCT_CPE_MAP: dict[str, tuple[str, str]] = {
    "apache httpd":   ("apache", "http_server"),
    "openssh":        ("openbsd", "openssh"),
    "nginx":          ("nginx", "nginx"),
    "mysql":          ("oracle", "mysql"),
    "mariadb":        ("mariadb", "mariadb"),
    "postgresql":     ("postgresql", "postgresql"),
    "vsftpd":         ("vsftpd", "vsftpd"),
    "proftpd":        ("proftpd", "proftpd"),
    "exim":           ("exim", "exim"),
    "dovecot":        ("dovecot", "dovecot"),
    "samba":          ("samba", "samba"),
    "isc bind":       ("isc", "bind"),
    "microsoft iis":  ("microsoft", "internet_information_services"),
}


def clean_version(version: str) -> str:
    # "6.6.1p1 Ubuntu 2ubuntu2.13" -> "6.6.1p1"
    if not version:
        return ""
    m = re.match(r"[0-9][A-Za-z0-9._\-+]*", version.strip())
    return m.group(0) if m else ""


def build_cpe(product: str, version: str) -> str | None:
    version = clean_version(version)
    if not product or not version:
        return None
    product_lower = product.lower()
    for key, (vendor, prod) in PRODUCT_CPE_MAP.items():
        if key in product_lower:
            return f"cpe:/a:{vendor}:{prod}:{version}"
    return None


def match_service(service: ServiceInfo, client: NVDClient,
                  max_results: int = 50) -> list[CVEInfo]:
    cpe_candidates: list[str] = []

    # 1) Bilinen üründen CPE inşa et
    built = build_cpe(service.product, service.version)
    if built:
        cpe_candidates.append(built)

    # 2) nmap uygulama-düzeyi CPE verdiyse ekle (OS CPE'lerini eleriz)
    if service.cpe.startswith("cpe:/a:") and service.cpe not in cpe_candidates:
        cpe_candidates.append(service.cpe)

    found: dict[str, CVEInfo] = {}
    for cpe in cpe_candidates:
        for cve in client.search_by_cpe(cpe, max_results=max_results):
            found[cve.cve_id] = cve

    # 3) CPE adayı yoksa keyword'e düş
    if not cpe_candidates and service.product:
        text = f"{service.product} {service.version}".strip()
        for cve in client.search_by_keyword(text, max_results=max_results):
            found[cve.cve_id] = cve

    return sorted(found.values(),
                  key=lambda c: c.cvss_score if c.cvss_score is not None else -1,
                  reverse=True)


# --- CLI test: python -m scanner.matcher ---
if __name__ == "__main__":
    client = NVDClient()
    fake_services = [
        ServiceInfo(host="test", port=80, protocol="tcp", state="open",
                    name="http", product="Apache httpd", version="2.4.7",
                    cpe="cpe:/a:apache:http_server:2.4.7"),
        ServiceInfo(host="test", port=22, protocol="tcp", state="open",
                    name="ssh", product="OpenSSH", version="6.6.1p1",
                    cpe="cpe:/o:linux:linux_kernel"),
    ]
    for svc in fake_services:
        print(f"\n=== {svc.product} {svc.version} (port {svc.port}) ===")
        print(f"    inşa edilen CPE: {build_cpe(svc.product, svc.version)}")
        cves = match_service(svc, client, max_results=10)
        print(f"    → {len(cves)} CVE, en kritik 3:")
        for cve in cves[:3]:
            print("       ", cve)
