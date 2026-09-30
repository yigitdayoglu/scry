"""Uyarılar: yeni kritik/KEV açıkta webhook ve/veya e-posta. Kanal yoksa no-op."""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

import requests

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

from .database import session_scope
from .models import Scan

log = logging.getLogger("scry")


def channels_configured() -> bool:
    return bool(config.ALERT_WEBHOOK_URL or (config.SMTP_HOST and config.ALERT_TO))


def notify(subject: str, body: str) -> list[str]:
    sent: list[str] = []

    if config.ALERT_WEBHOOK_URL:
        try:
            # "text" (Slack) + "content" (Discord); alıcı olmayanı yok sayar
            requests.post(config.ALERT_WEBHOOK_URL,
                          json={"text": f"*{subject}*\n{body}",
                                "content": f"**{subject}**\n{body}"},
                          timeout=10)
            sent.append("webhook")
        except requests.RequestException as e:
            log.error("Uyarı webhook'u başarısız: %s", e)

    if config.SMTP_HOST and config.ALERT_TO:
        try:
            msg = MIMEText(body, _charset="utf-8")
            msg["Subject"] = subject
            msg["From"] = config.ALERT_FROM
            msg["To"] = config.ALERT_TO
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as srv:
                srv.starttls()
                if config.SMTP_USER:
                    srv.login(config.SMTP_USER, config.SMTP_PASS or "")
                srv.send_message(msg)
            sent.append("email")
        except Exception as e:
            log.error("Uyarı e-postası başarısız: %s", e)

    return sent


def maybe_alert(scan_id: int) -> None:
    if not channels_configured():
        return

    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            return
        host = scan.target.host
        prev = (s.query(Scan)
                .filter(Scan.target_id == scan.target_id, Scan.id < scan.id,
                        Scan.status == "success")
                .order_by(Scan.id.desc()).first())
        prev_keys = set()
        if prev:
            prev_keys = {(f.port, f.cve_id) for f in prev.findings
                         if not f.is_false_positive}

        # Yeni + önemli (KEV ya da kritik)
        important = []
        for f in scan.findings:
            if f.is_false_positive:
                continue
            if (f.port, f.cve_id) not in prev_keys and (f.kev or f.severity == "KRITIK"):
                important.append((f.cve_id, f.severity, f.kev, f.port))

    if not important:
        return

    important.sort(key=lambda x: (0 if x[2] else 1))
    lines = []
    for cve_id, sev, kev, port in important[:15]:
        tag = "⚠ KEV " if kev else ""
        lines.append(f"• {tag}{cve_id} ({sev}, port {port})")
    extra = f"\n… ve {len(important) - 15} tane daha" if len(important) > 15 else ""

    subject = f"[Scry] {host}: {len(important)} yeni kritik/KEV açık"
    body = (f"{host} taramasında (tarama #{scan_id}) yeni öne çıkan açıklar:\n\n"
            + "\n".join(lines) + extra)

    sent = notify(subject, body)
    if sent:
        log.info("Tarama #%d: uyarı gönderildi (%s)", scan_id, ", ".join(sent))
