# ScamShield AI

ScamShield AI is a React/TypeScript/Vite frontend with a FastAPI backend, PostgreSQL persistence, and Redis-backed login rate limiting.

## Local development on Windows PowerShell

### Prerequisites

- Python and Node.js/npm installed.
- A reachable PostgreSQL database with the application's schema already initialized. These steps do not create databases or run migrations.
- A reachable Redis instance for login rate limiting. `REDIS_URL` is required by backend configuration; login requests need Redis available.

### Configure and run the backend

From the repository root, open a PowerShell terminal:

```powershell
cd backend
if (-not (Test-Path .env)) { Copy-Item ..\.env.example .env }
notepad .env
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Replace the unmistakable placeholders in `backend/.env` with local values. The example uses `127.0.0.1` for local PostgreSQL and Redis endpoints; adjust these endpoints to match your services. `backend/app/core/config.py` loads `.env` relative to the backend working directory. Keep `.env` private and do not commit it.

The interactive API documentation is at <http://127.0.0.1:8000/docs>. The API health endpoint is at <http://127.0.0.1:8000/api/v1/health>.

### Run the frontend

Open a second PowerShell terminal from the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (configured for port 5173). The frontend reads `VITE_API_BASE_URL`; when it is unset, `frontend/src/lib/api.ts` uses `http://127.0.0.1:8000/api/v1`. To override it, create `frontend/.env.local` with:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

`frontend/package.json` is the canonical frontend package manifest: its `dev`, `build`, and `preview` scripts are run from `frontend/`, alongside `frontend/vite.config.ts`. Root-level package and TypeScript configuration files also exist; these instructions do not use or modify them. The root `docker-compose.yml` is empty, so this repository currently has no usable Compose setup documented here.

## Scope notes

The backend provides the scan and account APIs used by the frontend; `/docs` lists the routes available in the running application. Configuration includes optional external-service API key settings, but this local setup does not configure or claim any external threat-intelligence integration. The setup steps above cover local development only, not production deployment.
