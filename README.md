# ScamShield AI

ScamShield AI provides a React/Vite client and a FastAPI backend for authenticated message-risk scans.

## Run locally (Windows PowerShell)

Configure `backend/.env` with the database, Redis, JWT secret, and `FRONTEND_ORIGIN=http://localhost:5173` settings. The backend loads this file from its working directory. Set `frontend/.env.local` to point `VITE_API_BASE_URL` at the backend API (normally `http://127.0.0.1:8000/api/v1`).

In one terminal:

```powershell
cd backend
py -m venv .venv  # Skip if the backend virtual environment already exists.
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (normally http://localhost:5173). The API health check is at `http://127.0.0.1:8000/api/v1/health` and the interactive API docs are at `http://127.0.0.1:8000/docs`.

## Main routes

- `/` — landing page
- `/login` — login
- `/dashboard` — authenticated security dashboard
- `/scan` — scan center
- `/scan/message` — message scanner
- `/scan/url` — URL scanner
- `/scan/qr` — QR scanner
- `/scan/screenshot` — screenshot scanner
- `/threat/:id` — persisted scan details
- `/history` — scan history
- `/reports` — threat report
- `/settings` — settings

## Current scope

Authentication, dashboard data, scan history, and message analysis use the FastAPI backend. The backend issues JWT access tokens, uses PostgreSQL for user and scan data, and Redis for login rate limits. URL, QR, and screenshot pages remain UI prototypes and do not yet have corresponding analysis APIs.
