import os
import re

from fastapi import HTTPException

from .config import settings

# extension -> (category, mime type). Anything not listed is rejected.
EXT_INFO = {
    "pdf": ("Documents", "application/pdf"),
    "txt": ("Documents", "text/plain"),
    "csv": ("Documents", "text/csv"),
    "docx": ("Documents", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "xlsx": ("Documents", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "pptx": ("Documents", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    "png": ("Images", "image/png"),
    "jpg": ("Images", "image/jpeg"),
    "jpeg": ("Images", "image/jpeg"),
    "gif": ("Images", "image/gif"),
    "zip": ("Archives", "application/zip"),
}
_ZIP = (b"PK\x03\x04",)
SIGNATURES = {
    "pdf": (b"%PDF-",), "png": (b"\x89PNG\r\n\x1a\n",), "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",), "gif": (b"GIF87a", b"GIF89a"),
    "zip": _ZIP, "docx": _ZIP, "xlsx": _ZIP, "pptx": _ZIP,
}
INLINE_EXT = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}   # safe to preview in browser


def safe_filename(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return name[:255]


def validate_upload(filename: str, data: bytes):
    """Server-side validation. Returns (clean_name, ext, category, mime)."""
    name = safe_filename(filename)
    if not name or "." not in name:
        raise HTTPException(400, "A file name with an extension is required")
    ext = name.rsplit(".", 1)[1].lower()
    if ext not in EXT_INFO:
        raise HTTPException(415, f"File type '.{ext}' is not allowed")
    if len(data) == 0:
        raise HTTPException(400, "Empty files are not allowed")
    if len(data) > settings.MAX_FILE_SIZE:
        raise HTTPException(413, f"File is larger than the {settings.MAX_FILE_SIZE // (1024*1024)} MB limit")
    sigs = SIGNATURES.get(ext)
    if sigs and not data.startswith(sigs):
        raise HTTPException(415, "File content does not match its extension")
    if ext in ("txt", "csv"):
        if b"\x00" in data[:8192]:
            raise HTTPException(415, "File content does not match its extension")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(415, "Text files must be UTF-8 encoded")
    category, mime = EXT_INFO[ext]
    return name, ext, category, mime
