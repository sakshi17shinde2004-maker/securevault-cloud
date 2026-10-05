import os
import pathlib
import sys
import tempfile
import uuid

TMP = tempfile.mkdtemp(prefix="securevault_test_")
os.environ.update({
    "DATABASE_URL": f"sqlite:///{TMP}/test.db",
    "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
    "UPLOAD_DIR": f"{TMP}/uploads",
    "MAX_FILE_SIZE_MB": "1",
    "DEFAULT_QUOTA_MB": "5",
    "ADMIN_USERNAME": "admin",
    "ADMIN_EMAIL": "admin@example.com",
    "ADMIN_PASSWORD": "Admin12345",
})
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

import pytest
from fastapi.testclient import TestClient

PASSWORD = "Passw0rdX"


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def make_user(client):
    def _make():
        name = "u" + uuid.uuid4().hex[:10]
        r = client.post("/api/auth/register", json={"username": name, "email": f"{name}@example.com", "password": PASSWORD})
        assert r.status_code == 201, r.text
        uid = r.json()["id"]
        r = client.post("/api/auth/login", json={"username": name, "password": PASSWORD})
        assert r.status_code == 200
        return {"id": uid, "name": name, "h": {"Authorization": "Bearer " + r.json()["access_token"]}}
    return _make


@pytest.fixture()
def admin_h(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin12345"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def pdf(size=2000):
    return b"%PDF-1.4\n" + os.urandom(size)


def png(size=2000):
    return b"\x89PNG\r\n\x1a\n" + os.urandom(size)


def up(client, h, name="doc.pdf", data=None, path="/api/files/upload", extra=None, headers=None):
    data = data if data is not None else pdf()
    hh = {**h, **(headers or {})}
    return client.post(path, headers=hh, files={"file": (name, data)}, data=extra or {})
