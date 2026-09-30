"""Web route'ları (blueprint)."""

from __future__ import annotations

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash)

from core.database import session_scope
from core.models import Target, Scan, Finding
from core import scheduler as sched_mod

bp = Blueprint("main", __name__)

# Önem seviyeleri (kritikten aza)
SEVERITY_ORDER = ["KRITIK", "YUKSEK", "ORTA", "DUSUK", "BILINMIYOR"]

# Zamanlama aralığı seçenekleri (dakika, etiket)
INTERVAL_CHOICES = [
    (30, "30 dakikada bir"), (60, "Saatte bir"), (180, "3 saatte bir"),
    (360, "6 saatte bir"), (720, "12 saatte bir"), (1440, "Günde bir"),
]


@bp.app_context_processor
def inject_globals():
    try:
        from core.scheduler import get_scheduler
        active = get_scheduler().running
    except Exception:
        active = False
    return {"scheduler_active": active}


def _empty_counts() -> dict[str, int]:
    return {sev: 0 for sev in SEVERITY_ORDER}


# --- Pano ---
@bp.route("/")
def dashboard():
    with session_scope() as s:
        targets = s.query(Target).order_by(Target.host).all()

        overall = _empty_counts()
        target_rows = []

        for t in targets:
            # En son başarılı tarama = güncel durum
            latest = (s.query(Scan)
                      .filter_by(target_id=t.id, status="success")
                      .order_by(Scan.id.desc()).first())

            counts = _empty_counts()
            confirmed = 0
            scan_id = None
            if latest:
                scan_id = latest.id
                for f in latest.findings:
                    if f.is_false_positive:
                        continue
                    counts[f.severity] = counts.get(f.severity, 0) + 1
                    overall[f.severity] += 1
                    if f.verification == "confirmed":
                        confirmed += 1

            target_rows.append({
                "id": t.id,
                "host": t.host,
                "enabled": t.enabled,
                "interval_minutes": t.interval_minutes,
                "last_scan_at": t.last_scan_at,
                "latest_scan_id": scan_id,
                "counts": counts,
                "confirmed": confirmed,
                "total": sum(counts.values()),
            })

        recent = []
        for sc in s.query(Scan).order_by(Scan.id.desc()).limit(10).all():
            crit = sum(1 for f in sc.findings
                       if f.severity == "KRITIK" and not f.is_false_positive)
            confirmed = sum(1 for f in sc.findings
                            if f.verification == "confirmed" and not f.is_false_positive)
            recent.append({
                "id": sc.id,
                "host": sc.target.host,
                "status": sc.status,
                "started_at": sc.started_at,
                "finished_at": sc.finished_at,
                "total": len(sc.findings),
                "crit": crit,
                "confirmed": confirmed,
            })

        stats = {"targets": len(targets), "scans": s.query(Scan).count()}

    return render_template("dashboard.html",
                           target_rows=target_rows, overall=overall,
                           recent=recent, stats=stats,
                           severity_order=SEVERITY_ORDER)


# --- Hedef yönetimi ---
@bp.route("/targets")
def targets():
    with session_scope() as s:
        rows = []
        for t in s.query(Target).order_by(Target.host).all():
            last = (s.query(Scan).filter_by(target_id=t.id)
                    .order_by(Scan.id.desc()).first())
            rows.append({
                "id": t.id, "host": t.host, "ports": t.ports,
                "interval_minutes": t.interval_minutes, "enabled": t.enabled,
                "last_scan_at": t.last_scan_at,
                "last_status": last.status if last else None,
            })
    return render_template("targets.html", targets=rows,
                           interval_choices=INTERVAL_CHOICES)


@bp.route("/targets/add", methods=["POST"])
def add_target():
    host = request.form.get("host", "").strip()
    ports = request.form.get("ports", "").strip() or None
    try:
        interval = int(request.form.get("interval", 360))
    except ValueError:
        interval = 360
    authorized = request.form.get("authorized") == "on"

    if not host:
        flash("Host boş olamaz.")
        return redirect(url_for("main.targets"))
    if not authorized:
        flash("Devam etmek için bu host'u taramaya yetkili olduğunu onaylamalısın.")
        return redirect(url_for("main.targets"))

    with session_scope() as s:
        if s.query(Target).filter_by(host=host).one_or_none():
            flash(f"'{host}' zaten ekli.")
            return redirect(url_for("main.targets"))
        t = Target(host=host, ports=ports, interval_minutes=interval, enabled=True)
        s.add(t)
        s.flush()
        tid = t.id

    sched_mod.schedule_target(tid, interval)
    flash(f"'{host}' eklendi, {_interval_label(interval)} otomatik taranacak.")
    return redirect(url_for("main.targets"))


@bp.route("/targets/<int:tid>/scan", methods=["POST"])
def scan_target(tid):
    if sched_mod.scan_now(tid):
        flash("Tarama başlatıldı. Sonuçlar birkaç dakika içinde panoda görünür.")
    else:
        flash("Hedef bulunamadı.")
    return redirect(url_for("main.targets"))


@bp.route("/targets/<int:tid>/toggle", methods=["POST"])
def toggle_target(tid):
    enabled = None
    interval = 360
    with session_scope() as s:
        t = s.get(Target, tid)
        if t:
            t.enabled = not t.enabled
            enabled, interval = t.enabled, t.interval_minutes
    if enabled is True:
        sched_mod.schedule_target(tid, interval)
        flash("Hedef etkinleştirildi.")
    elif enabled is False:
        sched_mod.unschedule_target(tid)
        flash("Hedef duraklatıldı (otomatik tarama kapatıldı).")
    return redirect(url_for("main.targets"))


@bp.route("/targets/<int:tid>/delete", methods=["POST"])
def delete_target(tid):
    sched_mod.unschedule_target(tid)
    with session_scope() as s:
        t = s.get(Target, tid)
        if t:
            s.delete(t)
    flash("Hedef ve taramaları silindi.")
    return redirect(url_for("main.targets"))


def _interval_label(minutes: int) -> str:
    for m, label in INTERVAL_CHOICES:
        if m == minutes:
            return label.lower()
    return f"{minutes} dakikada bir"


# --- Tarama detayı ---
@bp.route("/scans/<int:scan_id>")
def scan_detail(scan_id):
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            flash("Tarama bulunamadı.")
            return redirect(url_for("main.dashboard"))

        info = {
            "id": scan.id,
            "host": scan.target.host,
            "target_id": scan.target_id,
            "status": scan.status,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "error": scan.error,
        }

        counts = _empty_counts()
        confirmed = 0
        kev = 0
        fp = 0
        findings = []
        for f in scan.findings:
            findings.append({
                "id": f.id, "cve_id": f.cve_id, "cvss_score": f.cvss_score,
                "severity": f.severity, "description": f.description, "url": f.url,
                "port": f.port, "protocol": f.protocol, "service_name": f.service_name,
                "product": f.product, "version": f.version,
                "verification": f.verification,
                "kev": f.kev, "epss_score": f.epss_score,
                "is_false_positive": f.is_false_positive,
            })
            if f.is_false_positive:
                fp += 1
                continue
            counts[f.severity] = counts.get(f.severity, 0) + 1
            if f.verification == "confirmed":
                confirmed += 1
            if f.kev:
                kev += 1

        # Sıralama: yanlış pozitifler sona, KEV öne, sonra CVSS'e göre
        findings.sort(key=lambda x: (
            x["is_false_positive"],
            0 if x["kev"] else 1,
            -(x["cvss_score"] if x["cvss_score"] is not None else -1),
        ))

    return render_template("scan_detail.html", scan=info, findings=findings,
                           counts=counts, confirmed=confirmed, kev=kev, fp=fp,
                           total=sum(counts.values()),
                           severity_order=SEVERITY_ORDER)


@bp.route("/scans/<int:scan_id>/report")
def scan_report(scan_id):
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            flash("Tarama bulunamadı.")
            return redirect(url_for("main.dashboard"))

        counts = _empty_counts()
        kev = confirmed = 0
        findings = []
        for f in scan.findings:
            if f.is_false_positive:
                continue
            counts[f.severity] = counts.get(f.severity, 0) + 1
            if f.kev:
                kev += 1
            if f.verification == "confirmed":
                confirmed += 1
            findings.append({
                "cve_id": f.cve_id, "cvss_score": f.cvss_score, "severity": f.severity,
                "epss_score": f.epss_score, "kev": f.kev, "verification": f.verification,
                "port": f.port, "protocol": f.protocol, "product": f.product,
                "version": f.version, "description": f.description, "url": f.url,
            })
        findings.sort(key=lambda x: (
            0 if x["kev"] else 1,
            -(x["cvss_score"] if x["cvss_score"] is not None else -1)))

        info = {"id": scan.id, "host": scan.target.host, "status": scan.status,
                "started_at": scan.started_at, "finished_at": scan.finished_at}

    from datetime import datetime, timezone
    return render_template("report.html", scan=info, findings=findings,
                           counts=counts, kev=kev, confirmed=confirmed,
                           total=sum(counts.values()),
                           generated_at=datetime.now(timezone.utc),
                           severity_order=SEVERITY_ORDER)


@bp.route("/scans/<int:scan_id>/diff")
def scan_diff(scan_id):
    def _fdict(f):
        return {"cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
                "port": f.port, "product": f.product, "url": f.url, "kev": f.kev}

    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            flash("Tarama bulunamadı.")
            return redirect(url_for("main.dashboard"))

        prev = (s.query(Scan)
                .filter(Scan.target_id == scan.target_id, Scan.id < scan.id,
                        Scan.status == "success")
                .order_by(Scan.id.desc()).first())

        cur_map = {(f.port, f.cve_id): _fdict(f) for f in scan.findings
                   if not f.is_false_positive}
        prev_map = {}
        prev_info = None
        if prev:
            prev_info = {"id": prev.id, "started_at": prev.started_at}
            prev_map = {(f.port, f.cve_id): _fdict(f) for f in prev.findings
                        if not f.is_false_positive}

        new_keys = set(cur_map) - set(prev_map)
        resolved_keys = set(prev_map) - set(cur_map)

        def _sort(items):
            return sorted(items, key=lambda x: (
                0 if x["kev"] else 1,
                -(x["cvss_score"] if x["cvss_score"] is not None else -1)))

        new_findings = _sort([cur_map[k] for k in new_keys])
        resolved_findings = _sort([prev_map[k] for k in resolved_keys])
        unchanged = len(set(cur_map) & set(prev_map))

        info = {"id": scan.id, "host": scan.target.host,
                "started_at": scan.started_at}

    return render_template("scan_diff.html", scan=info, prev=prev_info,
                           new_findings=new_findings,
                           resolved_findings=resolved_findings,
                           unchanged=unchanged, severity_order=SEVERITY_ORDER)


@bp.route("/findings/<int:fid>/toggle-fp", methods=["POST"])
def toggle_fp(fid):
    scan_id = None
    with session_scope() as s:
        f = s.get(Finding, fid)
        if f:
            f.is_false_positive = not f.is_false_positive
            scan_id = f.scan_id
    if scan_id:
        return redirect(url_for("main.scan_detail", scan_id=scan_id))
    return redirect(url_for("main.dashboard"))
