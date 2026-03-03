from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db


class Target(db.Model):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # url, url_list, domain, ip, api_spec
    value: Mapped[str] = mapped_column(Text, nullable=False)
    api_spec_format: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # openapi_3, swagger_2, postman
    api_spec_content: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project: Mapped[Project] = relationship(back_populates="targets")

    __table_args__ = (
        db.Index("ix_targets_project_type", "project_id", "target_type"),
        db.Index("ix_targets_project_active", "project_id", "is_active"),
    )


from dimsum.models.project import Project  # noqa: E402, F401
