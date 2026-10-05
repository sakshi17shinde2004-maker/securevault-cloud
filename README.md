# SecureVault Cloud

Secure file vault: FastAPI + MySQL + Bootstrap. Local first (uploads/ folder), AWS (S3 + RDS) later.

## Folders
- `backend/`   FastAPI code (app/routers, models, security, storage)
- `frontend/`  HTML + CSS + JS + Bootstrap (served by FastAPI)
- `database/`  init.sql (creates the MySQL database and user)
- `uploads/`   real files (local mode only, never committed to Git)
- `tests/`     automated system tests (pytest)

## Run (Windows)
```
python -m venv venv
venv\Scripts\activate
pip install -r backend\requirements.txt
copy backend\.env.example backend\.env      (then edit SECRET_KEY and passwords)
mysql -u root -p < database\init.sql
cd backend
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000  (API docs: http://127.0.0.1:8000/docs)

## Tests
```
pip install -r backend\requirements-dev.txt
pytest tests -v
```
Tests use a temporary SQLite database, so your MySQL data is never touched.

## Storage switch
`STORAGE_BACKEND=local` -> uploads/ folder.
`STORAGE_BACKEND=s3`    -> Amazon S3 (use an IAM Role, no keys in code).
