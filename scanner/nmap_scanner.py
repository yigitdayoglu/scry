"""nmap `-sV` sarmalayıcısı: açık servisleri ServiceInfo listesine çevirir."""

from __future__ import annotations

import sys
from dataclasses import dataclass

import nmap

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore


@dataclass
class ServiceInfo:
    host: str
    port: int
    protocol: str
    state: str
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""

    def __str__(self) -> str:
        v = f" {self.version}" if self.version else ""
        p = self.product or self.name
        cpe = f"  [{self.cpe}]" if self.cpe else "  [CPE yok]"
        return f"{self.port}/{self.protocol}  {self.state}  {p}{v}{cpe}"


class ScanError(Exception):
    pass


def scan_host(host: str, ports: str | None = None,
              arguments: str = "-sV -Pn") -> list[ServiceInfo]:
    host = host.strip()

    # --- Güvenlik korkuluğu: yalnızca izinli hedefler ---
    if not config.is_target_allowed(host):
        raise ScanError(
            f"'{host}' izin listesinde değil. config.py > TARGET_ALLOWLIST'e ekle."
        )

    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=host, ports=ports, arguments=arguments)
    except nmap.PortScannerError as exc:
        raise ScanError(f"nmap çalıştırılamadı: {exc}") from exc

    services: list[ServiceInfo] = []
    for scanned_host in scanner.all_hosts():
        host_data = scanner[scanned_host]
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                p = host_data[proto][port]
                if p.get("state") != "open":
                    continue
                services.append(ServiceInfo(
                    host=scanned_host,
                    port=port,
                    protocol=proto,
                    state=p.get("state", ""),
                    name=p.get("name", ""),
                    product=p.get("product", ""),
                    version=p.get("version", ""),
                    extrainfo=p.get("extrainfo", ""),
                    cpe=_extract_cpe(p.get("cpe", "")),
                ))
    return services


def _extract_cpe(raw) -> str:
    if not raw:
        return ""
    if isinstance(raw, list):
        return raw[0] if raw else ""
    return str(raw)


# --- CLI: python -m scanner.nmap_scanner scanme.nmap.org 22,80 ---
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    port_arg = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"[*] Taranıyor: {target} (portlar: {port_arg or 'ilk 1000'})")
    try:
        results = scan_host(target, ports=port_arg)
    except ScanError as e:
        print(f"[!] Hata: {e}")
        sys.exit(1)

    if not results:
        print("[-] Açık port bulunamadı.")
    else:
        print(f"[+] {len(results)} açık servis bulundu:\n")
        for svc in results:
            print("   ", svc)
