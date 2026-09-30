"""Veritabanı bağlantısı: engine, oturum ve hafif şema göçü."""

from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore

from .models import Base

engine = create_engine(config.DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)
    _ensure_columns()


def _ensure_columns() -> None:
    # create_all var olan tabloya yeni sütun eklemez; eksik sütunları ALTER ile ekle.
    from sqlalchemy import text

    migrations = {
        "findings": {
            "verification": "VARCHAR(20) DEFAULT 'unverified'",
            "kev": "BOOLEAN DEFAULT 0",
            "epss_score": "FLOAT",
        },
    }
    with engine.begin() as conn:
        for table, columns in migrations.items():
            existing = {row[1] for row in
                        conn.execute(text(f"PRAGMA table_info({table})"))}
            for col, ddl in columns.items():
                if col not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))


@contextmanager
def session_scope():
    # Blok başarılıysa commit, hata olursa rollback, her hâlde kapat.
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
