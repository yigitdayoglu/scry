import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# --- NVD API ---
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip() or None
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- Veritabanı ---
_db_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'scry.db'}")
if _db_url.startswith("sqlite:///") and not _db_url.startswith("sqlite:////"):
    _rel = _db_url[len("sqlite:///"):]
    if not os.path.isabs(_rel):
        _db_url = f"sqlite:///{(BASE_DIR / _rel).resolve()}"
DATABASE_URL = _db_url

# --- Flask ---
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "gelistirme-anahtari")

# --- Loglama ---
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "scry.log"

# --- Nuclei aktif doğrulama ---
NUCLEI_VERIFY = os.getenv("NUCLEI_VERIFY", "true").strip().lower() not in ("false", "0", "no")
NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "180"))

# --- Zenginleştirme (CISA KEV + EPSS) ---
ENRICH_ENABLED = os.getenv("ENRICH", "true").strip().lower() not in ("false", "0", "no")

# --- Uyarılar (opsiyonel) ---
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip() or None
SMTP_HOST = os.getenv("SMTP_HOST", "").strip() or None
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip() or None
SMTP_PASS = os.getenv("SMTP_PASS", "").strip() or None
ALERT_FROM = os.getenv("ALERT_FROM", "").strip() or (SMTP_USER or "scry@localhost")
ALERT_TO = os.getenv("ALERT_TO", "").strip() or None

# --- Hedef izin listesi ---
TARGET_ALLOWLIST = {
    "scanme.nmap.org",
    "127.0.0.1",
    "localhost",
}


def is_target_allowed(host: str) -> bool:
    return host.strip().lower() in {h.lower() for h in TARGET_ALLOWLIST}
