from datetime import timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import client_ip, current_user, vault_ok, vault_required
from ..models import FileRecord, User, utcnow
from ..security import create_token, hash_password, verify_password
from ..services import create_file, file_out, log, read_upload

router = APIRouter(prefix="/api/vault", tags=["vault"])
MAX_ATTEMPTS, LOCK_MINUTES = 5, 5


class PinIn(BaseModel):
    pin: str = Field(pattern=r"^\d{4,8}$")


class MoveIn(BaseModel):
    to_vault: bool


@router.get("/status")
def status(user: User = Depends(current_user), unlocked: bool = Depends(vault_ok)):
    return {"configured": bool(user.vault_pin_hash), "unlocked": unlocked}


@router.post("/setup", status_code=201)
def setup(body: PinIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.vault_pin_hash:
        raise HTTPException(400, "Vault PIN is already set")
    user.vault_pin_hash = hash_password(body.pin)
    log(db, user.id, "vault_setup", None, "", client_ip(request))
    db.commit()
    return {"configured": True}


@router.post("/unlock")
def unlock(body: PinIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ip = client_ip(request)
    if not user.vault_pin_hash:
        raise HTTPException(400, "Set up your Vault PIN first")
    if user.vault_locked_until and user.vault_locked_until > utcnow():
        raise HTTPException(429, "Too many wrong PINs. Try again in a few minutes.")
    if not verify_password(body.pin, user.vault_pin_hash):
        user.vault_failed_attempts += 1
        if user.vault_failed_attempts >= MAX_ATTEMPTS:
            user.vault_locked_until = utcnow() + timedelta(minutes=LOCK_MINUTES)
            user.vault_failed_attempts = 0
        log(db, user.id, "vault_unlock_failed", None, "", ip)
        db.commit()
        raise HTTPException(401, "Wrong Vault PIN")
    user.vault_failed_attempts, user.vault_locked_until = 0, None
    log(db, user.id, "vault_access", None, "unlocked", ip)
    db.commit()
    return {"vault_token": create_token(user.id, settings.VAULT_TOKEN_MINUTES, "vault"),
            "expires_in_minutes": settings.VAULT_TOKEN_MINUTES}


@router.get("/files", dependencies=[Depends(vault_required)])
def vault_files(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = (db.query(FileRecord).filter(FileRecord.owner_id == user.id, FileRecord.is_vault.is_(True),
                                        FileRecord.is_deleted.is_(False))
            .order_by(FileRecord.created_at.desc()).all())
    return [file_out(f) for f in rows]


@router.post("/upload", status_code=201, dependencies=[Depends(vault_required)])
def vault_upload(request: Request, file: UploadFile = File(...), allow_duplicate: bool = Form(False),
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = read_upload(file)
    return file_out(create_file(db, user, file.filename, data, True, allow_duplicate, client_ip(request)))


@router.post("/files/{file_id}/move", dependencies=[Depends(vault_required)])
def move(file_id: int, body: MoveIn, request: Request, user: User = Depends(current_user),
         db: Session = Depends(get_db)):
    f = db.get(FileRecord, file_id)
    if not f or f.owner_id != user.id or f.is_deleted:
        raise HTTPException(404, "File not found")
    f.is_vault = body.to_vault
    log(db, user.id, "vault_move_in" if body.to_vault else "vault_move_out", f.id, f.original_name,
        client_ip(request))
    db.commit()
    return file_out(f)
