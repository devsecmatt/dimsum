from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    config_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_configurations.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # pending, running, paused, completed, failed, cancelled
    scan_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="full"
    )  # full, quick, enumeration, source_only
    target_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    progress_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary_stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project: Mapped[Project] = relationship(back_populates="scans")
    config: Mapped[ScanConfiguration | None] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        db.Index("ix_scans_project_status", "project_id", "status"),
        db.Index("ix_scans_project_created", "project_id", "created_at"),
    )


from dimsum.models.project import Project  # noqa: E402, F401
from dimsum.models.scan_config import ScanConfiguration  # noqa: E402, F401
from dimsum.models.finding import Finding  # noqa: E402, F401
