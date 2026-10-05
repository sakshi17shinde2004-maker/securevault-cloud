from datetime import datetime, timezone

from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey, Index,
                        Integer, String, UniqueConstraint)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(30), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)          # bcrypt hash, never plain text
    role = Column(String(10), nullable=False, default="USER")    # USER | ADMIN
    quota_bytes = Column(BigInteger, nullable=False)
    used_bytes = Column(BigInteger, nullable=False, default=0)
    vault_pin_hash = Column(String(100))
    vault_failed_attempts = Column(Integer, nullable=False, default=0)
    vault_locked_until = Column(DateTime)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class FileRecord(Base):
    """Metadata only. The real bytes live in uploads/ (local) or S3 (AWS)."""
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    original_name = Column(String(255), nullable=False)
    storage_path = Column(String(300), nullable=False, unique=True)   # unique object key
    mime_type = Column(String(100), nullable=False)
    extension = Column(String(10), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False)
    category = Column(String(30), nullable=False)
    is_vault = Column(Boolean, nullable=False, default=False)
    is_deleted = Column(Boolean, nullable=False, default=False)
    deleted_at = Column(DateTime)
    current_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    versions = relationship("FileVersion", cascade="all, delete-orphan",
                            order_by="FileVersion.version_number.desc()")
    shares = relationship("ShareLink", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_files_owner_hash", "owner_id", "sha256"),)


class FileVersion(Base):
    """Previous (archived) versions of a file. The current version stays in `files`."""
    __tablename__ = "file_versions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_id = Column(Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    original_name = Column(String(255), nullable=False)
    storage_path = Column(String(300), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (UniqueConstraint("file_id", "version_number", name="uq_file_version"),)


class ShareLink(Base):
    __tablename__ = "share_links"
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_id = Column(Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)     # only the hash is stored
    permission = Column(String(10), nullable=False, default="download")  # view | download
    expires_at = Column(DateTime, nullable=False)
    max_downloads = Column(Integer)
    download_count = Column(Integer, nullable=False, default=0)
    revoked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action = Column(String(40), nullable=False)
    file_id = Column(Integer)          # no FK on purpose: logs must survive permanent delete
    detail = Column(String(255))
    ip_address = Column(String(45))
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
