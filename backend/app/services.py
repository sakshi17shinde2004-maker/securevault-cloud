import uuid
from urllib.parse import quote

from fastapi import HTTPException, Response, UploadFile
from sqlalchemy.orm import Session

from .config import settings
from .models import ActivityLog, FileRecord, FileVersion, User, utcnow
from .security import sha256_bytes
from .storage import get_storage
from .validators import validate_upload


def log(db: Session, user_id, action: str, file_id=None, detail: str = "", ip=None):
    """Activity log. NEVER pass passwords, PINs or tokens in `detail`."""
    db.add(ActivityLog(user_id=user_id, action=action, file_id=file_id,
                       detail=(detail or "")[:255], ip_address=ip))


def iso(dt):
    return dt.isoformat() if dt else None


def file_out(f: FileRecord) -> dict:
    return {"id": f.id, "name": f.original_name, "extension": f.extension, "category": f.category,
            "size": f.size_bytes, "sha256": f.sha256, "version": f.current_version,
            "is_vault": f.is_vault, "created_at": iso(f.created_at),
            "updated_at": iso(f.updated_at), "deleted_at": iso(f.deleted_at)}


def user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "email": u.email, "role": u.role,
            "quota_bytes": u.quota_bytes, "used_bytes": u.used_bytes, "is_active": u.is_active,
            "vault_configured": bool(u.vault_pin_hash), "created_at": iso(u.created_at)}


def read_upload(upload: UploadFile) -> bytes:
    # read one byte more than the limit so oversize files are detected without loading everything
    return upload.file.read(settings.MAX_FILE_SIZE + 1)


def total_size(f: FileRecord) -> int:
    return f.size_bytes + sum(v.size_bytes for v in f.versions)


def check_quota(user: User, extra: int):
    if user.used_bytes + extra > user.quota_bytes:
        raise HTTPException(413, "Storage quota exceeded")


def _new_key(user: User, ext: str) -> str:
    return f"{user.id}/{uuid.uuid4().hex}.{ext}"


def create_file(db: Session, user: User, filename: str, data: bytes, is_vault: bool,
                allow_duplicate: bool, ip) -> FileRecord:
    name, ext, category, mime = validate_upload(filename, data)
    digest = sha256_bytes(data)
    if not allow_duplicate:
        dup = (db.query(FileRecord)
               .filter(FileRecord.owner_id == user.id, FileRecord.sha256 == digest,
                       FileRecord.is_deleted.is_(False), FileRecord.is_vault.is_(is_vault))
               .first())
        if dup:
            raise HTTPException(409, f"Duplicate file: identical content already uploaded as '{dup.original_name}'")
    check_quota(user, len(data))
    key = _new_key(user, ext)
    storage = get_storage()
    storage.save(key, data, mime)
    f = FileRecord(owner_id=user.id, original_name=name, storage_path=key, mime_type=mime,
                   extension=ext, size_bytes=len(data), sha256=digest, category=category,
                   is_vault=is_vault)
    user.used_bytes += len(data)
    db.add(f)
    try:
        db.flush()
        log(db, user.id, "vault_upload" if is_vault else "upload", f.id, name, ip)
        db.commit()
    except Exception:
        db.rollback()
        storage.delete(key)
        raise
    db.refresh(f)
    return f


def add_version(db: Session, user: User, f: FileRecord, filename: str, data: bytes, ip) -> FileRecord:
    name, ext, _, mime = validate_upload(filename, data)
    if ext != f.extension:
        raise HTTPException(400, f"A new version must have the same file type (.{f.extension})")
    digest = sha256_bytes(data)
    if digest == f.sha256:
        raise HTTPException(409, "This content is identical to the current version")
    check_quota(user, len(data))
    key = _new_key(user, ext)
    storage = get_storage()
    storage.save(key, data, mime)
    next_no = max([f.current_version] + [v.version_number for v in f.versions]) + 1
    f.versions.append(FileVersion(version_number=f.current_version, original_name=f.original_name,
                                  storage_path=f.storage_path, size_bytes=f.size_bytes,
                                  sha256=f.sha256, created_at=f.updated_at or f.created_at))
    f.storage_path, f.size_bytes, f.sha256 = key, len(data), digest
    f.original_name, f.current_version = name, next_no
    user.used_bytes += len(data)
    try:
        log(db, user.id, "version_upload", f.id, f"v{next_no}", ip)
        db.commit()
    except Exception:
        db.rollback()
        storage.delete(key)
        raise
    db.refresh(f)
    return f


def restore_version(db: Session, user: User, f: FileRecord, number: int, ip) -> FileRecord:
    v = next((x for x in f.versions if x.version_number == number), None)
    if not v:
        raise HTTPException(404, "Version not found")
    # current version is archived, chosen old version becomes current (total storage unchanged)
    f.versions.append(FileVersion(version_number=f.current_version, original_name=f.original_name,
                                  storage_path=f.storage_path, size_bytes=f.size_bytes,
                                  sha256=f.sha256, created_at=f.updated_at or f.created_at))
    f.storage_path, f.size_bytes, f.sha256 = v.storage_path, v.size_bytes, v.sha256
    f.original_name, f.current_version = v.original_name, v.version_number
    f.versions.remove(v)
    log(db, user.id, "version_restore", f.id, f"restored v{number}", ip)
    db.commit()
    db.refresh(f)
    return f


def soft_delete(db: Session, user: User, f: FileRecord, ip):
    if f.is_deleted:
        raise HTTPException(400, "File is already in the Recycle Bin")
    f.is_deleted, f.deleted_at = True, utcnow()
    user.used_bytes = max(0, user.used_bytes - total_size(f))   # bin items do not use quota
    log(db, user.id, "delete", f.id, f.original_name, ip)
    db.commit()


def restore_from_trash(db: Session, user: User, f: FileRecord, ip):
    if not f.is_deleted:
        raise HTTPException(400, "File is not in the Recycle Bin")
    size = total_size(f)
    check_quota(user, size)
    f.is_deleted, f.deleted_at = False, None
    user.used_bytes += size
    log(db, user.id, "restore", f.id, f.original_name, ip)
    db.commit()


def permanent_delete(db: Session, user: User, f: FileRecord, ip):
    if not f.is_deleted:
        raise HTTPException(400, "Move the file to the Recycle Bin first")
    storage = get_storage()
    for key in [f.storage_path] + [v.storage_path for v in f.versions]:
        storage.delete(key)
    log(db, user.id, "permanent_delete", f.id, f.original_name, ip)
    db.delete(f)
    db.commit()


def file_response(data: bytes, name: str, mime: str, inline: bool) -> Response:
    disposition = "inline" if inline else "attachment"
    headers = {
        "Content-Disposition": f"{disposition}; filename*=UTF-8''{quote(name)}",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }
    return Response(content=data, media_type=mime, headers=headers)
