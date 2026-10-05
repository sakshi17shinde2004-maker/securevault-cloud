from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, require_admin
from ..models import ActivityLog, FileRecord, User
from ..services import iso, log, user_out

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


class UserPatch(BaseModel):
    quota_mb: Optional[int] = Field(None, ge=1, le=102400)
    is_active: Optional[bool] = None


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    return {"users": db.query(func.count(User.id)).scalar(),
            "files": db.query(func.count(FileRecord.id)).filter(FileRecord.is_deleted.is_(False)).scalar(),
            "used_bytes": int(db.query(func.coalesce(func.sum(User.used_bytes), 0)).scalar()),
            "log_entries": db.query(func.count(ActivityLog.id)).scalar()}


@router.get("/users")
def users(db: Session = Depends(get_db)):
    counts = dict(db.query(FileRecord.owner_id, func.count(FileRecord.id))
                  .filter(FileRecord.is_deleted.is_(False)).group_by(FileRecord.owner_id).all())
    return [{**user_out(u), "file_count": counts.get(u.id, 0)} for u in db.query(User).order_by(User.id)]


@router.patch("/users/{user_id}")
def patch_user(user_id: int, body: UserPatch, request: Request, admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    if body.is_active is False and u.id == admin.id:
        raise HTTPException(400, "You cannot disable your own account")
    if body.quota_mb is not None:
        u.quota_bytes = body.quota_mb * 1024 * 1024
    if body.is_active is not None:
        u.is_active = body.is_active
    log(db, admin.id, "admin_update_user", None, f"user #{u.id}", client_ip(request))
    db.commit()
    return user_out(u)


@router.get("/logs")
def logs(limit: int = 200, db: Session = Depends(get_db)):
    rows = (db.query(ActivityLog, User.username).outerjoin(User, User.id == ActivityLog.user_id)
            .order_by(ActivityLog.id.desc()).limit(min(max(limit, 1), 1000)).all())
    return [{"id": r.id, "user": name, "action": r.action, "file_id": r.file_id, "detail": r.detail,
             "ip": r.ip_address, "created_at": iso(r.created_at)} for r, name in rows]
