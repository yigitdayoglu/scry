"""SQLAlchemy modelleri: Target 1-* Scan 1-* Finding."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, Float, Boolean, Integer, DateTime
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(255), unique=True)
    ports: Mapped[str | None] = mapped_column(String(255), nullable=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=360)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target {self.host} her {self.interval_minutes}dk>"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running/success/failed
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)

    target: Mapped["Target"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan #{self.id} {self.status} ({len(self.findings)} bulgu)>"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))

    # --- Servis ---
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str] = mapped_column(String(100), default="")
    product: Mapped[str] = mapped_column(String(200), default="")
    version: Mapped[str] = mapped_column(String(100), default="")
    cpe: Mapped[str] = mapped_column(String(255), default="")

    # --- Zafiyet ---
    cve_id: Mapped[str] = mapped_column(String(30))
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="BILINMIYOR")
    description: Mapped[str] = mapped_column(String(1000), default="")
    url: Mapped[str] = mapped_column(String(255), default="")

    # --- Durum / zenginleştirme ---
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    verification: Mapped[str] = mapped_column(String(20), default="unverified")  # unverified/confirmed
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding {self.cve_id} {self.severity} port={self.port}>"
