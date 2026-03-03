from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from dimsum.models.compat import GUID, JSONType
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db


class SourceUpload(db.Model):
    __tablename__ = "source_uploads"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    language: Mapped[str] = mapped_column(String(20), nullable=False)  # python, javascript, typescript
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, running, completed, failed
    extracted_params: Mapped[list] = mapped_column(JSONType, default=list)
    extracted_routes: Mapped[list] = mapped_column(JSONType, default=list)
    risk_indicators: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project: Mapped[Project] = relationship(back_populates="source_uploads")


from dimsum.models.project import Project  # noqa: E402, F401
