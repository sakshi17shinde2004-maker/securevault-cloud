import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import client_ip, current_user
from ..models import ActivityLog, User
from ..security import DUMMY_HASH, create_token, hash_password, verify_password
from ..services import iso, log, user_out

router = APIRouter(prefix="/api", tags=["auth"])


class RegisterIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_]{3,30}$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def strong(cls, v: str):
        if not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
            raise ValueError("Password must contain at least one letter and one digit")
        return v


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)


@router.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    exists = db.query(User).filter(or_(User.username == body.username,
                                       User.email == body.email.lower())).first()
    if exists:
        raise HTTPException(409, "Username or email is already registered")
    user = User(username=body.username, email=body.email.lower(),
                password_hash=hash_password(body.password), role="USER",
                quota_bytes=settings.DEFAULT_QUOTA)
    db.add(user)
    db.flush()
    log(db, user.id, "register", None, "", client_ip(request))
    db.commit()
    return user_out(user)


@router.post("/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    user = db.query(User).filter(or_(User.username == body.username,
                                     User.email == body.username.lower())).first()
    ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if not user or not ok:
        # log only the user id (never the typed text: people sometimes type passwords in the username box)
        log(db, user.id if user else None, "login_failed", None,
            "wrong password" if user else "unknown user", ip)
        db.commit()
        raise HTTPException(401, "Invalid username or password")
    if not user.is_active:
        raise HTTPException(403, "This account is disabled")
    log(db, user.id, "login", None, "", ip)
    db.commit()
    return {"access_token": create_token(user.id, settings.ACCESS_TOKEN_MINUTES),
            "token_type": "bearer", "user": user_out(user)}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return user_out(user)


@router.get("/me/logs")
def my_logs(limit: int = 100, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = (db.query(ActivityLog).filter(ActivityLog.user_id == user.id)
            .order_by(ActivityLog.id.desc()).limit(min(max(limit, 1), 500)).all())
    return [{"id": r.id, "action": r.action, "file_id": r.file_id, "detail": r.detail,
             "ip": r.ip_address, "created_at": iso(r.created_at)} for r in rows]
