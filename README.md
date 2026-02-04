# Django Tasks API

This project is a Django REST API with Tasks CRUD, token auth, JWT auth (optional), email verification, password reset, and Swagger/OpenAPI docs (optional).

## Quick Start (Local)
1. Install dependencies:
```bash
make install
```
2. Reset DB and migrate (recommended for custom user model):
```bash
rm db.sqlite3
make migrate
```
3. Seed demo data:
```bash
make seed
```
4. Run the server:
```bash
make run
```

## Swagger/OpenAPI (Beautiful API Docs)
Swagger is provided by `drf-spectacular` and is optional. If installed, you get:
- JSON schema: `http://localhost:8000/api/schema/`
- Swagger UI: `http://localhost:8000/api/docs/`

### Install Swagger Dependencies
```bash
pip install drf-spectacular
```

### Using Swagger UI to Test APIs
1. Open `http://localhost:8000/api/docs/`.
2. Click **Authorize** (top right) and enter your token:
   - Token auth: `Token YOUR_TOKEN`
   - JWT auth: `Bearer YOUR_JWT_ACCESS`
3. Expand an endpoint, click **Try it out**, fill the body, then **Execute**.
4. Responses and curl examples will show below.

## Auth & Testing Flow (Recommended)
### 1) Register
`POST /api/auth/register/`
```json
{
  "username": "demo_user",
  "email": "demo@example.com",
  "password": "password123"
}
```

### 2) Verify Email
Check terminal output for UID and TOKEN and call:
`POST /api/auth/verify/confirm/`
```json
{
  "uid": "YOUR_UID",
  "token": "YOUR_TOKEN"
}
```

### 3) Login (Token Auth)
`POST /api/auth/login/`
```json
{
  "username": "demo_user",
  "password": "password123"
}
```
Response contains `token` for Authorization header.

### 4) Login (JWT Auth, Optional)
Requires `djangorestframework-simplejwt`.
`POST /api/auth/jwt/create/`
```json
{
  "username": "demo_user",
  "password": "password123"
}
```
Use `access` as `Bearer` token.

## Tasks API (Examples)
### List Tasks
`GET /api/tasks/`

### Create Task
`POST /api/tasks/`
```json
{
  "title": "Sample task",
  "description": "Do the thing",
  "is_completed": false
}
```

## Health Check
`GET /api/health/`
```json
{"status": "ok"}
```

## Tools & Commands
- `make install` – install dependencies
- `make migrate` – create/apply migrations
- `make seed` – create demo user + tasks
- `make run` – start server

## Notes
- Swagger and JWT endpoints are only enabled if the packages are installed.
- Tokens expire after 24 hours (configurable in `core/settings.py`).
