import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .config import settings
from .database import Base, SessionLocal, engine
from .models import User
from .routers import admin, auth, files, share, vault
from .security import hash_password

logger = logging.getLogger("securevault")


def seed_admin():
    if not (settings.ADMIN_USERNAME and settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD):
        logger.warning("ADMIN_* not set in .env - no admin account created")
        return
    with SessionLocal() as db:
        if db.query(User).filter(User.role == "ADMIN").first():
            return
        db.add(User(username=settings.ADMIN_USERNAME, email=settings.ADMIN_EMAIL.lower(),
                    password_hash=hash_password(settings.ADMIN_PASSWORD), role="ADMIN",
                    quota_bytes=settings.DEFAULT_QUOTA))
        db.commit()
        logger.warning("Admin account '%s' created", settings.ADMIN_USERNAME)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    seed_admin()
    yield


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.get("/api/health")
def health():
    return {"status": "ok", "storage": settings.STORAGE_BACKEND}


for r in (auth.router, files.router, share.router, vault.router, admin.router):
    app.include_router(r)

# Frontend is served last so /api/* routes always win
app.mount("/", StaticFiles(directory=settings.FRONTEND_DIR, html=True), name="frontend")
