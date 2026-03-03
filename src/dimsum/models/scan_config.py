from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db


class ScanConfiguration(db.Model):
    __tablename__ = "scan_configurations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled_plugins: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=10)
    request_delay_ms: Mapped[int] = mapped_column(Integer, default=100)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    max_depth: Mapped[int] = mapped_column(Integer, default=3)
    custom_headers: Mapped[dict] = mapped_column(JSONB, default=dict)
    auth_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    wordlist_ids: Mapped[list] = mapped_column(JSONB, default=list)
    enable_enumeration: Mapped[bool] = mapped_column(Boolean, default=False)
    enable_source_analysis: Mapped[bool] = mapped_column(Boolean, default=False)
    asvs_level: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    project: Mapped[Project] = relationship(back_populates="scan_configs")
    scans: Mapped[list[Scan]] = relationship(back_populates="config")


from dimsum.models.project import Project  # noqa: E402, F401
from dimsum.models.scan import Scan  # noqa: E402, F401
