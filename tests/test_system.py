import os
from datetime import timedelta

from conftest import PASSWORD, pdf, png, up


def used(client, u):
    return client.get("/api/auth/me", headers=u["h"]).json()["used_bytes"]


# ---------- authentication ----------
def test_register_login_valid_and_invalid(client, make_user):
    u = make_user()
    bad = client.post("/api/auth/register", json={"username": "x" + u["name"], "email": "a@example.com", "password": "short"})
    assert bad.status_code == 422
    nodigit = client.post("/api/auth/register", json={"username": "x" + u["name"], "email": "b@example.com", "password": "onlyletters"})
    assert nodigit.status_code == 422
    dup = client.post("/api/auth/register", json={"username": u["name"], "email": "c@example.com", "password": PASSWORD})
    assert dup.status_code == 409
    assert client.post("/api/auth/login", json={"username": u["name"], "password": "WrongPass1"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "nobody", "password": PASSWORD}).status_code == 401


def test_password_is_hashed_in_db(client, make_user):
    u = make_user()
    from app.database import SessionLocal
    from app.models import User
    with SessionLocal() as db:
        row = db.get(User, u["id"])
        assert row.password_hash != PASSWORD and row.password_hash.startswith("$2")


def test_sql_injection_login(client):
    r = client.post("/api/auth/login", json={"username": "' OR '1'='1", "password": "' OR '1'='1"})
    assert r.status_code == 401


def test_unauthorized_access(client, make_user):
    assert client.get("/api/files").status_code == 401
    assert client.get("/api/files", headers={"Authorization": "Bearer garbage"}).status_code == 401
    u = make_user()
    assert client.get("/api/admin/users", headers=u["h"]).status_code == 403
    assert client.get("/api/admin/logs", headers=u["h"]).status_code == 403


# ---------- upload / validation ----------
def test_upload_download_and_metadata(client, make_user):
    u = make_user()
    data = pdf(5000)
    r = up(client, u["h"], "My Report.pdf", data)
    assert r.status_code == 201, r.text
    f = r.json()
    import hashlib
    assert f["sha256"] == hashlib.sha256(data).hexdigest() and f["name"] == "My Report.pdf"
    assert "storage_path" not in f
    assert any(x["id"] == f["id"] for x in client.get("/api/files", headers=u["h"]).json())
    d = client.get(f"/api/files/{f['id']}/download", headers=u["h"])
    assert d.status_code == 200 and d.content == data
    # stored on disk under a unique random name, not the original name
    from app.database import SessionLocal
    from app.models import FileRecord
    with SessionLocal() as db:
        rec = db.get(FileRecord, f["id"])
        assert "My Report" not in rec.storage_path and rec.storage_path.startswith(f"{u['id']}/")


def test_unsupported_and_fake_files(client, make_user):
    u = make_user()
    assert up(client, u["h"], "virus.exe", b"MZ" + os.urandom(100)).status_code == 415
    assert up(client, u["h"], "script.php", b"<?php ?>").status_code == 415
    assert up(client, u["h"], "fake.pdf", b"this is not a pdf").status_code == 415
    assert up(client, u["h"], "empty.pdf", b"").status_code == 400
    assert up(client, u["h"], "noext", b"hello").status_code == 400


def test_large_file_rejected(client, make_user):
    u = make_user()
    assert up(client, u["h"], "big.pdf", pdf(1024 * 1024 + 10)).status_code == 413


def test_quota_limit_and_accounting(client, make_user, admin_h):
    u = make_user()
    r = client.patch(f"/api/admin/users/{u['id']}", headers=admin_h, json={"quota_mb": 1})
    assert r.status_code == 200
    assert up(client, u["h"], "a.pdf", pdf(600_000)).status_code == 201
    assert up(client, u["h"], "b.pdf", pdf(600_000)).status_code == 413
    assert used(client, u) > 600_000


def test_duplicate_detection(client, make_user):
    u = make_user()
    data = pdf(3000)
    assert up(client, u["h"], "one.pdf", data).status_code == 201
    r = up(client, u["h"], "two.pdf", data)
    assert r.status_code == 409 and "Duplicate" in r.json()["detail"]
    assert up(client, u["h"], "two.pdf", data, extra={"allow_duplicate": "true"}).status_code == 201
    other = make_user()
    assert up(client, other["h"], "one.pdf", data).status_code == 201   # other users unaffected


# ---------- isolation ----------
def test_user_cannot_access_other_users_files(client, make_user):
    a, b = make_user(), make_user()
    fid = up(client, a["h"]).json()["id"]
    assert client.get(f"/api/files/{fid}/download", headers=b["h"]).status_code == 404
    assert client.delete(f"/api/files/{fid}", headers=b["h"]).status_code == 404
    assert client.post(f"/api/files/{fid}/shares", headers=b["h"], json={}).status_code == 404
    assert client.get(f"/api/files/{fid}/versions", headers=b["h"]).status_code == 404
    assert all(x["id"] != fid for x in client.get("/api/files", headers=b["h"]).json())


# ---------- recycle bin ----------
def test_recycle_bin_flow(client, make_user):
    u = make_user()
    before = used(client, u)
    f = up(client, u["h"], "bin.pdf", pdf(4000)).json()
    after_upload = used(client, u)
    assert after_upload > before
    assert client.delete(f"/api/files/{f['id']}", headers=u["h"]).status_code == 204
    assert used(client, u) == before
    assert all(x["id"] != f["id"] for x in client.get("/api/files", headers=u["h"]).json())
    assert any(x["id"] == f["id"] for x in client.get("/api/trash", headers=u["h"]).json())
    assert client.get(f"/api/files/{f['id']}/download", headers=u["h"]).status_code == 404
    assert client.post(f"/api/trash/{f['id']}/restore", headers=u["h"]).status_code == 200
    assert used(client, u) == after_upload
    # permanent delete only from the bin
    assert client.delete(f"/api/trash/{f['id']}", headers=u["h"]).status_code == 400
    client.delete(f"/api/files/{f['id']}", headers=u["h"])
    assert client.delete(f"/api/trash/{f['id']}", headers=u["h"]).status_code == 204
    assert client.post(f"/api/trash/{f['id']}/restore", headers=u["h"]).status_code == 404


# ---------- versions ----------
def test_versioning_and_restore(client, make_user):
    u = make_user()
    v1, v2 = pdf(3000), pdf(3500)
    f = up(client, u["h"], "ver.pdf", v1).json()
    r = client.post(f"/api/files/{f['id']}/versions", headers=u["h"], files={"file": ("ver.pdf", v2)})
    assert r.status_code == 201 and r.json()["version"] == 2
    assert client.get(f"/api/files/{f['id']}/download", headers=u["h"]).content == v2
    vs = client.get(f"/api/files/{f['id']}/versions", headers=u["h"]).json()
    assert [v["version"] for v in vs["versions"]] == [1]
    # same content / wrong type rejected
    assert client.post(f"/api/files/{f['id']}/versions", headers=u["h"], files={"file": ("ver.pdf", v2)}).status_code == 409
    assert client.post(f"/api/files/{f['id']}/versions", headers=u["h"], files={"file": ("x.png", png())}).status_code in (400, 415)
    rr = client.post(f"/api/files/{f['id']}/versions/1/restore", headers=u["h"])
    assert rr.status_code == 200 and rr.json()["version"] == 1
    assert client.get(f"/api/files/{f['id']}/download", headers=u["h"]).content == v1
    vs = client.get(f"/api/files/{f['id']}/versions", headers=u["h"]).json()
    assert [v["version"] for v in vs["versions"]] == [2]


# ---------- sharing ----------
def test_share_link_expiry_revoke_and_permissions(client, make_user):
    u = make_user()
    data = pdf(2500)
    f = up(client, u["h"], "share.pdf", data).json()
    s = client.post(f"/api/files/{f['id']}/shares", headers=u["h"], json={"permission": "download", "expires_minutes": 30}).json()
    tok = s["token"]
    assert client.get(f"/api/share/{tok}").json()["name"] == "share.pdf"       # no login needed
    c = client.get(f"/api/share/{tok}/content")
    assert c.status_code == 200 and c.content == data and "attachment" in c.headers["content-disposition"]
    assert client.get("/api/share/not-a-real-token").status_code == 404
    # view-only link is inline
    sv = client.post(f"/api/files/{f['id']}/shares", headers=u["h"], json={"permission": "view"}).json()
    assert "inline" in client.get(f"/api/share/{sv['token']}/content").headers["content-disposition"]
    # download limit
    sl = client.post(f"/api/files/{f['id']}/shares", headers=u["h"], json={"max_downloads": 1}).json()
    assert client.get(f"/api/share/{sl['token']}/content").status_code == 200
    assert client.get(f"/api/share/{sl['token']}/content").status_code == 404
    # expiry
    from app.database import SessionLocal
    from app.models import ShareLink, utcnow
    with SessionLocal() as db:
        db.get(ShareLink, s["id"]).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert client.get(f"/api/share/{tok}").status_code == 404
    # revoke
    assert client.delete(f"/api/shares/{sv['id']}", headers=u["h"]).status_code == 204
    assert client.get(f"/api/share/{sv['token']}").status_code == 404
    # raw token is not stored in DB
    with SessionLocal() as db:
        assert db.query(ShareLink).filter(ShareLink.token_hash == tok).first() is None


# ---------- vault ----------
def test_secure_vault(client, make_user):
    u = make_user()
    h = u["h"]
    assert up(client, h, "v.pdf", path="/api/vault/upload").status_code == 403         # locked
    assert client.get("/api/vault/files", headers=h).status_code == 403
    assert client.post("/api/vault/setup", headers=h, json={"pin": "12"}).status_code == 422
    assert client.post("/api/vault/setup", headers=h, json={"pin": "482913"}).status_code == 201
    assert client.post("/api/vault/unlock", headers=h, json={"pin": "000000"}).status_code == 401
    tok = client.post("/api/vault/unlock", headers=h, json={"pin": "482913"}).json()["vault_token"]
    vh = {"X-Vault-Token": tok}
    f = up(client, h, "secret.pdf", pdf(2222), path="/api/vault/upload", headers=vh)
    assert f.status_code == 201 and f.json()["is_vault"] is True
    fid = f.json()["id"]
    assert all(x["id"] != fid for x in client.get("/api/files", headers=h).json())    # hidden from normal list
    assert client.get(f"/api/files/{fid}/download", headers=h).status_code == 403       # needs PIN token
    assert client.get(f"/api/files/{fid}/download", headers={**h, **vh}).status_code == 200
    assert client.get("/api/vault/files", headers={**h, **vh}).json()[0]["id"] == fid
    assert client.post(f"/api/files/{fid}/shares", headers={**h, **vh}, json={}).status_code == 400
    # another user cannot use my vault token
    other = make_user()
    assert client.get("/api/vault/files", headers={**other["h"], **vh}).status_code == 403


def test_vault_lockout_after_wrong_pins(client, make_user):
    u = make_user()
    client.post("/api/vault/setup", headers=u["h"], json={"pin": "1357"})
    codes = [client.post("/api/vault/unlock", headers=u["h"], json={"pin": "9999"}).status_code for _ in range(5)]
    assert codes == [401] * 5
    assert client.post("/api/vault/unlock", headers=u["h"], json={"pin": "1357"}).status_code == 429


# ---------- admin & logs ----------
def test_admin_access_and_logs_have_no_secrets(client, make_user, admin_h):
    u = make_user()
    up(client, u["h"])
    client.post("/api/auth/login", json={"username": u["name"], "password": "WrongPass1"})
    assert client.get("/api/admin/stats", headers=admin_h).json()["users"] >= 2
    users = client.get("/api/admin/users", headers=admin_h).json()
    assert any(x["id"] == u["id"] for x in users)
    logs = client.get("/api/admin/logs?limit=1000", headers=admin_h).json()
    actions = {l["action"] for l in logs}
    assert {"login", "login_failed", "upload", "register"} <= actions
    blob = str(logs)
    assert PASSWORD not in blob and "WrongPass1" not in blob and "Admin12345" not in blob
    mine = client.get("/api/me/logs", headers=u["h"]).json()
    assert all(True for _ in mine) and len(mine) >= 3


def test_disabled_user_cannot_login_or_use_token(client, make_user, admin_h):
    u = make_user()
    client.patch(f"/api/admin/users/{u['id']}", headers=admin_h, json={"is_active": False})
    assert client.get("/api/files", headers=u["h"]).status_code == 401
    assert client.post("/api/auth/login", json={"username": u["name"], "password": PASSWORD}).status_code == 403
