import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / "backend" / ".env")


def _path(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else ROOT / p


class Settings:
    APP_NAME = "SecureVault Cloud"
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://securevault:SecureVault_123@localhost:3306/securevault_db",
    )
    SECRET_KEY = os.getenv("SECRET_KEY", "")
    ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
    VAULT_TOKEN_MINUTES = int(os.getenv("VAULT_TOKEN_MINUTES", "10"))

    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").lower()
    UPLOAD_DIR = _path(os.getenv("UPLOAD_DIR", "uploads"))
    S3_BUCKET = os.getenv("S3_BUCKET", "")
    AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")

    MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
    DEFAULT_QUOTA = int(os.getenv("DEFAULT_QUOTA_MB", "100")) * 1024 * 1024

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

    FRONTEND_DIR = ROOT / "frontend"


settings = Settings()

if not settings.SECRET_KEY or settings.SECRET_KEY.startswith("change-me"):
    raise RuntimeError(
        "SECRET_KEY is not set. Copy backend/.env.example to backend/.env and set a long random SECRET_KEY."
    )
