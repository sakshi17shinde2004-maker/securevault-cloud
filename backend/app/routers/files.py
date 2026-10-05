import secrets
from datetime import timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, current_user, vault_ok
from ..models import FileRecord, ShareLink, User, utcnow
from ..security import hash_token
from ..services import (add_version, create_file, file_out, file_response, iso, log,
                        permanent_delete, read_upload, restore_from_trash, restore_version,
                        soft_delete)
from ..storage import get_storage
from ..validators import INLINE_EXT

router = APIRouter(prefix="/api", tags=["files"])


def get_owned(db: Session, user: User, file_id: int, unlocked: bool) -> FileRecord:
    f = db.get(FileRecord, file_id)
    if not f or f.owner_id != user.id:          # 404 (not 403) so other users' file ids are not revealed
        raise HTTPException(404, "File not found")
    if f.is_vault and not unlocked:
        raise HTTPException(403, "Vault is locked. Enter your Vault PIN.")
    return f


@router.get("/files")
def list_files(q: Optional[str] = None, category: Optional[str] = None,
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    qs = db.query(FileRecord).filter(FileRecord.owner_id == user.id,
                                     FileRecord.is_deleted.is_(False),
                                     FileRecord.is_vault.is_(False))
    if q:
        qs = qs.filter(FileRecord.original_name.contains(q, autoescape=True))
    if category:
        qs = qs.filter(FileRecord.category == category)
    return [file_out(f) for f in qs.order_by(FileRecord.created_at.desc()).all()]


@router.post("/files/upload", status_code=201)
def upload(request: Request, file: UploadFile = File(...), allow_duplicate: bool = Form(False),
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = read_upload(file)
    return file_out(create_file(db, user, file.filename, data, False, allow_duplicate, client_ip(request)))


def _serve(file_id, request, user, db, unlocked, inline_wanted):
    f = get_owned(db, user, file_id, unlocked)
    if f.is_deleted:
        raise HTTPException(404, "File not found")
    data = get_storage().read(f.storage_path)
    inline = inline_wanted and f.extension in INLINE_EXT
    log(db, user.id, "view" if inline else "download", f.id, f.original_name, client_ip(request))
    db.commit()
    return file_response(data, f.original_name, f.mime_type, inline)


@router.get("/files/{file_id}/download")
def download(file_id: int, request: Request, user: User = Depends(current_user),
             db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    return _serve(file_id, request, user, db, unlocked, False)


@router.get("/files/{file_id}/view")
def view(file_id: int, request: Request, user: User = Depends(current_user),
         db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    return _serve(file_id, request, user, db, unlocked, True)


@router.delete("/files/{file_id}", status_code=204)
def delete_file(file_id: int, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    soft_delete(db, user, f, client_ip(request))


# ---------------- Recycle Bin ----------------
@router.get("/trash")
def list_trash(user: User = Depends(current_user), db: Session = Depends(get_db),
               unlocked: bool = Depends(vault_ok)):
    qs = db.query(FileRecord).filter(FileRecord.owner_id == user.id, FileRecord.is_deleted.is_(True))
    if not unlocked:
        qs = qs.filter(FileRecord.is_vault.is_(False))
    return [file_out(f) for f in qs.order_by(FileRecord.deleted_at.desc()).all()]


@router.post("/trash/{file_id}/restore")
def trash_restore(file_id: int, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    restore_from_trash(db, user, f, client_ip(request))
    return file_out(f)


@router.delete("/trash/{file_id}", status_code=204)
def trash_purge(file_id: int, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    permanent_delete(db, user, f, client_ip(request))


# ---------------- Versions ----------------
@router.get("/files/{file_id}/versions")
def list_versions(file_id: int, user: User = Depends(current_user), db: Session = Depends(get_db),
                  unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    return {"current": {"version": f.current_version, "name": f.original_name, "size": f.size_bytes,
                        "sha256": f.sha256, "created_at": iso(f.updated_at)},
            "versions": [{"version": v.version_number, "name": v.original_name, "size": v.size_bytes,
                          "sha256": v.sha256, "created_at": iso(v.created_at)} for v in f.versions]}


@router.post("/files/{file_id}/versions", status_code=201)
def upload_version(file_id: int, request: Request, file: UploadFile = File(...),
                   user: User = Depends(current_user), db: Session = Depends(get_db),
                   unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    if f.is_deleted:
        raise HTTPException(400, "Restore the file from the Recycle Bin first")
    data = read_upload(file)
    return file_out(add_version(db, user, f, file.filename, data, client_ip(request)))


@router.post("/files/{file_id}/versions/{number}/restore")
def version_restore(file_id: int, number: int, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    if f.is_deleted:
        raise HTTPException(400, "Restore the file from the Recycle Bin first")
    return file_out(restore_version(db, user, f, number, client_ip(request)))


# ---------------- Secure share links ----------------
class ShareIn(BaseModel):
    permission: Literal["view", "download"] = "download"
    expires_minutes: int = Field(60, ge=1, le=60 * 24 * 7)
    max_downloads: Optional[int] = Field(None, ge=1, le=1000)


def _share_out(s: ShareLink) -> dict:
    return {"id": s.id, "permission": s.permission, "expires_at": iso(s.expires_at),
            "max_downloads": s.max_downloads, "download_count": s.download_count,
            "revoked": s.revoked, "created_at": iso(s.created_at)}


@router.post("/files/{file_id}/shares", status_code=201)
def create_share(file_id: int, body: ShareIn, request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db), unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    if f.is_vault:
        raise HTTPException(400, "Vault files cannot be shared")
    if f.is_deleted:
        raise HTTPException(400, "Deleted files cannot be shared")
    if body.permission == "view" and f.extension not in INLINE_EXT:
        raise HTTPException(400, "View-only links work for images, PDF and TXT files only")
    token = secrets.token_urlsafe(32)
    s = ShareLink(file_id=f.id, created_by=user.id, token_hash=hash_token(token),
                  permission=body.permission, expires_at=utcnow() + timedelta(minutes=body.expires_minutes),
                  max_downloads=body.max_downloads)
    db.add(s)
    db.flush()
    log(db, user.id, "share", f.id, f"{body.permission}, {body.expires_minutes} min", client_ip(request))
    db.commit()
    return {**_share_out(s), "token": token}     # the raw token is shown only once


@router.get("/files/{file_id}/shares")
def list_shares(file_id: int, user: User = Depends(current_user), db: Session = Depends(get_db),
                unlocked: bool = Depends(vault_ok)):
    f = get_owned(db, user, file_id, unlocked)
    return [_share_out(s) for s in sorted(f.shares, key=lambda x: x.id, reverse=True)]


@router.delete("/shares/{share_id}", status_code=204)
def revoke_share(share_id: int, request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    s = db.get(ShareLink, share_id)
    if not s or s.created_by != user.id:
        raise HTTPException(404, "Share link not found")
    s.revoked = True
    log(db, user.id, "share_revoke", s.file_id, f"link #{s.id}", client_ip(request))
    db.commit()
