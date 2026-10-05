from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip
from ..models import FileRecord, ShareLink, utcnow
from ..security import hash_token
from ..services import file_response, iso, log
from ..storage import get_storage
from ..validators import INLINE_EXT

router = APIRouter(prefix="/api/share", tags=["public share"])
INVALID = "This link is invalid or has expired"


def _resolve(db: Session, token: str):
    s = db.query(ShareLink).filter(ShareLink.token_hash == hash_token(token)).first()
    if (not s or s.revoked or s.expires_at < utcnow()
            or (s.max_downloads is not None and s.download_count >= s.max_downloads)):
        raise HTTPException(404, INVALID)
    f = db.get(FileRecord, s.file_id)
    if not f or f.is_deleted or f.is_vault:
        raise HTTPException(404, INVALID)
    return s, f


@router.get("/{token}")
def info(token: str, db: Session = Depends(get_db)):
    s, f = _resolve(db, token)
    return {"name": f.original_name, "size": f.size_bytes, "extension": f.extension,
            "permission": s.permission, "expires_at": iso(s.expires_at)}


@router.get("/{token}/content")
def content(token: str, request: Request, db: Session = Depends(get_db)):
    s, f = _resolve(db, token)
    inline = s.permission == "view"
    if inline and f.extension not in INLINE_EXT:
        raise HTTPException(403, "This link does not allow this file to be opened")
    data = get_storage().read(f.storage_path)
    s.download_count += 1
    log(db, None, "share_access", f.id, f"link #{s.id} ({s.permission})", client_ip(request))
    db.commit()
    return file_response(data, f.original_name, f.mime_type, inline)
