from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from dimsum.models.compat import GUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    plugin_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # critical, high, medium, low, info
    confidence: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # confirmed, firm, tentative
    cwe_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(200), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_dump: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_dump: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="findings")
    asvs_checks: Mapped[list[ASVSCheck]] = relationship(
        secondary="finding_asvs_checks", back_populates="findings"
    )

    __table_args__ = (
        db.Index("ix_findings_scan_severity", "scan_id", "severity"),
        db.Index("ix_findings_scan_plugin", "scan_id", "plugin_id"),
        db.Index("ix_findings_scan_fp", "scan_id", "is_false_positive"),
    )


from dimsum.models.scan import Scan  # noqa: E402, F401
from dimsum.models.asvs_check import ASVSCheck  # noqa: E402, F401
