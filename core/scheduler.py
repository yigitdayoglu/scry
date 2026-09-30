"""Zamanlama (APScheduler): her aktif hedefi kendi aralığında otomatik tarar."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

from .database import session_scope
from .models import Target
from .scan_runner import run_scan

log = logging.getLogger("scry")

# İşleri tarama verisinden ayrı dosyada tut (SQLite kilit çakışmasını önler)
JOBSTORE_URL = f"sqlite:///{config.BASE_DIR / 'jobs.sqlite'}"

_scheduler: BackgroundScheduler | None = None


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(
            jobstores={"default": SQLAlchemyJobStore(url=JOBSTORE_URL)},
            job_defaults={
                "coalesce": True,
                "misfire_grace_time": 300,
                "max_instances": 1,
            },
        )
    return _scheduler


def start() -> None:
    sched = get_scheduler()
    if not sched.running:
        sched.start()
        log.info("Scheduler başlatıldı.")
    sync_targets()


def shutdown() -> None:
    sched = get_scheduler()
    if sched.running:
        sched.shutdown(wait=False)
        log.info("Scheduler durduruldu.")


def _job_id(target_id: int) -> str:
    return f"target:{target_id}"


# APScheduler bu fonksiyonu 'core.scheduler:scan_target_job' yolu olarak saklar;
# bu yüzden modül düzeyinde ve import edilebilir olmalı.
def scan_target_job(target_id: int) -> None:
    with session_scope() as s:
        target = s.get(Target, target_id)
        if target is None or not target.enabled:
            return
        host, ports = target.host, target.ports
    log.info("[scheduler] Otomatik tarama tetiklendi: %s", host)
    run_scan(host, ports=ports)


def scan_now(target_id: int) -> bool:
    # Tek seferlik iş; web isteği beklemeden döner, tarama arka planda çalışır.
    with session_scope() as s:
        if s.get(Target, target_id) is None:
            return False
    sched = get_scheduler()
    if not sched.running:
        sched.start()
    sched.add_job(
        scan_target_job, args=[target_id],
        id=f"scan-now:{target_id}:{int(time.time())}",
        next_run_time=datetime.now(timezone.utc),
        misfire_grace_time=60,
    )
    log.info("[scheduler] Manuel tarama kuyruğa alındı: hedef #%d", target_id)
    return True


def schedule_target(target_id: int, interval_minutes: int,
                    run_now: bool = False) -> None:
    sched = get_scheduler()
    kwargs = {}
    if run_now:
        kwargs["next_run_time"] = datetime.now(timezone.utc)
    sched.add_job(
        scan_target_job,
        trigger="interval",
        minutes=interval_minutes,
        args=[target_id],
        id=_job_id(target_id),
        replace_existing=True,
        **kwargs,
    )
    log.info("[scheduler] Hedef #%d her %d dk'da bir zamanlandı.",
             target_id, interval_minutes)


def unschedule_target(target_id: int) -> None:
    sched = get_scheduler()
    if sched.get_job(_job_id(target_id)):
        sched.remove_job(_job_id(target_id))
        log.info("[scheduler] Hedef #%d zamanlaması kaldırıldı.", target_id)


def sync_targets() -> None:
    # Aktif hedeflere job kur, pasif/silinmişlerin job'unu kaldır.
    with session_scope() as s:
        targets = s.query(Target).all()
        active_ids = set()
        for t in targets:
            if t.enabled:
                active_ids.add(t.id)
                schedule_target(t.id, t.interval_minutes)

    sched = get_scheduler()
    for job in sched.get_jobs():
        if job.id.startswith("target:"):
            tid = int(job.id.split(":")[1])
            if tid not in active_ids:
                sched.remove_job(job.id)


def list_jobs() -> list[dict]:
    sched = get_scheduler()
    return [{"id": job.id, "next_run": str(job.next_run_time)}
            for job in sched.get_jobs()]
