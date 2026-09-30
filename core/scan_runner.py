"""Orkestrasyon: tara -> eşleştir -> zenginleştir -> doğrula -> kaydet -> uyar."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

from .database import init_db, session_scope
from .models import Target, Scan, Finding
from scanner.nmap_scanner import scan_host, ScanError
from scanner.matcher import match_service
from scanner.nvd_client import NVDClient
from scanner.nuclei_verifier import verify as nuclei_verify, is_available as nuclei_available
from scanner.enrichment import enrich as enrich_cves


# --- Loglama (dosyaya döndürmeli + konsola) ---
def setup_logging() -> logging.Logger:
    logger = logging.getLogger("scry")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        config.LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(fmt)

    console = logging.StreamHandler()
    console.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console)
    return logger


log = setup_logging()


def _target_exists(host: str) -> bool:
    with session_scope() as s:
        return s.query(Target).filter_by(host=host).one_or_none() is not None


def get_or_create_target(session, host: str, ports: str | None = None,
                         interval_minutes: int = 360) -> Target:
    target = session.query(Target).filter_by(host=host).one_or_none()
    if target is None:
        target = Target(host=host, ports=ports, interval_minutes=interval_minutes)
        session.add(target)
        session.flush()
        log.info("Yeni hedef eklendi: %s", host)
    return target


def run_scan(host: str, ports: str | None = None) -> int:
    init_db()

    # --- Güvenlik korkuluğu: allowlist ya da bilinçli eklenmiş hedef ---
    if not (config.is_target_allowed(host) or _target_exists(host)):
        log.warning("Reddedildi (yetkisiz hedef): %s", host)
        raise ScanError(
            f"'{host}' yetkili değil. Arayüzden 'Hedef Ekle' ile ekleyip "
            f"taramaya yetkili olduğunu onayla."
        )

    # --- 1) 'running' taramayı oluştur ---
    with session_scope() as s:
        target = get_or_create_target(s, host, ports)
        scan = Scan(target=target, status="running")
        s.add(scan)
        s.flush()
        scan_id = scan.id
        scan_ports = target.ports
    log.info("Tarama #%d başladı: %s (portlar: %s)", scan_id, host,
             scan_ports or "ilk 1000")

    # --- 2) Ağ işi (DB transaction'ı dışında) ---
    try:
        services = scan_host(host, ports=scan_ports)
        log.info("Tarama #%d: %d açık servis bulundu", scan_id, len(services))

        client = NVDClient()
        finding_rows: list[Finding] = []
        for svc in services:
            cves = match_service(svc, client)
            log.info("  %s:%d %s %s → %d CVE", host, svc.port,
                     svc.product or svc.name, svc.version, len(cves))
            for cve in cves:
                finding_rows.append(Finding(
                    port=svc.port, protocol=svc.protocol,
                    service_name=svc.name, product=svc.product,
                    version=svc.version, cpe=svc.cpe,
                    cve_id=cve.cve_id, cvss_score=cve.cvss_score,
                    severity=cve.severity, description=cve.description,
                    url=cve.url,
                ))

        # --- Zenginleştirme (KEV + EPSS) ---
        if config.ENRICH_ENABLED and finding_rows:
            cve_ids = list({r.cve_id for r in finding_rows})
            kev_set, epss = enrich_cves(cve_ids)
            for r in finding_rows:
                r.kev = r.cve_id in kev_set
                r.epss_score = epss.get(r.cve_id)
            kev_count = sum(1 for r in finding_rows if r.kev)
            log.info("Tarama #%d: zenginleştirildi (%d KEV)", scan_id, kev_count)

        # --- Aktif doğrulama (nuclei) ---
        if config.NUCLEI_VERIFY and finding_rows:
            if nuclei_available():
                cve_ids = list({r.cve_id for r in finding_rows})
                log.info("Tarama #%d: %d CVE nuclei ile doğrulanıyor...",
                         scan_id, len(cve_ids))
                confirmed = nuclei_verify(host, services, cve_ids)
                for r in finding_rows:
                    if r.cve_id in confirmed:
                        r.verification = "confirmed"
                log.info("Tarama #%d: %d CVE aktif DOĞRULANDI", scan_id, len(confirmed))
            else:
                log.info("Tarama #%d: nuclei kurulu değil, doğrulama atlandı", scan_id)
    except Exception as exc:
        log.error("Tarama #%d başarısız: %s", scan_id, exc)
        _finish_scan(scan_id, status="failed", error=str(exc)[:500])
        return scan_id

    # --- 3) Sonuçları yaz, taramayı 'success' yap ---
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        for row in finding_rows:
            row.scan_id = scan_id
            s.add(row)
        scan.status = "success"
        scan.finished_at = _utcnow()
        scan.target.last_scan_at = scan.finished_at

    total = len(finding_rows)
    crit = sum(1 for r in finding_rows if r.severity == "KRITIK")
    high = sum(1 for r in finding_rows if r.severity == "YUKSEK")
    log.info("Tarama #%d bitti: %d bulgu (%d kritik, %d yüksek)",
             scan_id, total, crit, high)

    # --- Uyarılar (kanal yoksa no-op) ---
    try:
        from core.alerts import maybe_alert
        maybe_alert(scan_id)
    except Exception as e:
        log.error("Uyarı adımı hatası: %s", e)

    return scan_id


def _finish_scan(scan_id: int, status: str, error: str | None = None) -> None:
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan:
            scan.status = status
            scan.error = error
            scan.finished_at = _utcnow()


def _utcnow():
    from .models import utcnow
    return utcnow()


# --- CLI: python -m core.scan_runner scanme.nmap.org 22,80 ---
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    port_arg = sys.argv[2] if len(sys.argv) > 2 else None
    try:
        sid = run_scan(target, ports=port_arg)
        print(f"\n[+] Tarama #{sid} tamamlandı. Sonuçlar veritabanında.")
    except ScanError as e:
        print(f"[!] {e}")
        sys.exit(1)
