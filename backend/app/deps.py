from typing import Optional

from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .security import decode_token

bearer = HTTPBearer(auto_error=False)


def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    if not creds:
        raise HTTPException(401, "Authentication required")
    payload = decode_token(creds.credentials, "access")
    if not payload:
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(401, "Account not found or disabled")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "ADMIN":
        raise HTTPException(403, "Admin access required")
    return user


def vault_ok(x_vault_token: Optional[str] = Header(None), user: User = Depends(current_user)) -> bool:
    if not x_vault_token:
        return False
    payload = decode_token(x_vault_token, "vault")
    return bool(payload and payload["sub"] == str(user.id))


def vault_required(unlocked: bool = Depends(vault_ok)) -> bool:
    if not unlocked:
        raise HTTPException(403, "Vault is locked. Enter your Vault PIN.")
    return True


def client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None
