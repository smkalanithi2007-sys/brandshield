from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Brand(Base):
    __tablename__ = "monitored_brands"
    __table_args__ = (
        UniqueConstraint("user_id", "name", "domain"),
        CheckConstraint(
            "monitoring_interval_hours IS NULL OR "
            "(monitoring_interval_hours >= 24 AND "
            "monitoring_interval_hours <= 168)",
            name="valid_monitoring_interval",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    domain: Mapped[str] = mapped_column(String(255), default="")
    external_lookup_consent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    monitoring_interval_hours: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    next_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    brand_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitored_brands.id", ondelete="SET NULL"), nullable=True
    )
    brand_name: Mapped[str] = mapped_column(String(100))
    domain: Mapped[str] = mapped_column(String(255), default="")
    scan_status: Mapped[str] = mapped_column(String(32))
    provider_results: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True
    )
    brand_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitored_brands.id", ondelete="SET NULL"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(32), default="Needs review")
    title: Mapped[str] = mapped_column(String(500))
    url: Mapped[str] = mapped_column(Text)
    details: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
