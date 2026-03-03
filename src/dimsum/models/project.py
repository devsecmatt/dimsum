from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dimsum.extensions import db


class Project(db.Model):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    owner: Mapped[User] = relationship(back_populates="projects")
    targets: Mapped[list[Target]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scan_configs: Mapped[list[ScanConfiguration]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    source_uploads: Mapped[list[SourceUpload]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


# Deferred imports for type resolution
from dimsum.models.user import User  # noqa: E402, F401
from dimsum.models.target import Target  # noqa: E402, F401
from dimsum.models.scan import Scan  # noqa: E402, F401
from dimsum.models.scan_config import ScanConfiguration  # noqa: E402, F401
from dimsum.models.source_upload import SourceUpload  # noqa: E402, F401
