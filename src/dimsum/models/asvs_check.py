from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db

# Association table for many-to-many Finding <-> ASVSCheck
finding_asvs_checks = db.Table(
    "finding_asvs_checks",
    db.Column("finding_id", UUID(as_uuid=True), ForeignKey("findings.id"), primary_key=True),
    db.Column("asvs_check_id", UUID(as_uuid=True), ForeignKey("asvs_checks.id"), primary_key=True),
    db.Column("status", String(10), nullable=False, default="fail"),  # pass, fail, partial
)


class ASVSCheck(db.Model):
    __tablename__ = "asvs_checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asvs_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    chapter: Mapped[int] = mapped_column(Integer, nullable=False)
    section: Mapped[str] = mapped_column(String(10), nullable=False)
    requirement: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[int] = mapped_column(Integer, nullable=False)  # 1, 2, or 3
    cwe_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    can_be_automated: Mapped[bool] = mapped_column(Boolean, default=False)
    plugin_ids: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    findings: Mapped[list[Finding]] = relationship(
        secondary="finding_asvs_checks", back_populates="asvs_checks"
    )


from dimsum.models.finding import Finding  # noqa: E402, F401
