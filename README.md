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

Open the local URL printed by Vite (configured for port 5173). The frontend reads `VITE_API_BASE_URL`; in development only, it defaults to `http://127.0.0.1:8000/api/v1`. Production builds require this variable to point to the reachable API base (including `/api/v1`), or server-backed actions show a configuration error. Copy `frontend/.env.example` to `frontend/.env.local` to configure local development:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

For the Netlify site, set the build environment variable `VITE_API_BASE_URL` to the deployed FastAPI base URL including `/api/v1` (for example, `https://<your-api-host>/api/v1`). The repository does not contain the deployed backend hostname, so replace the example with the actual public API host in Netlify. In the backend hosting environment, set `FRONTEND_ORIGIN=https://scamshield-project-ai.netlify.app` so CORS allows this exact site origin. Keep API credentials and signing/encryption secrets out of all `VITE_*` variables.

Netlify SPA fallback rules are in `frontend/public/_redirects`; publish the frontend build output so direct visits and refreshes at `/login` and `/register` resolve to the React app.

`frontend/package.json` is the canonical frontend package manifest: its `dev`, `build`, and `preview` scripts are run from `frontend/`, alongside `frontend/vite.config.ts`. Root-level package and TypeScript configuration files also exist; these instructions do not use or modify them. The root `docker-compose.yml` is empty, so this repository currently has no usable Compose setup documented here.

The frontend includes a standalone PWA manifest, local app icons, an offline notice, and a service worker that caches only the generic app shell and same-origin static assets. It does not cache API responses or queue scans. Production installation and service workers require HTTPS; localhost is allowed for development. Phones also need a reachable `VITE_API_BASE_URL`. iPhone installation uses Safari's Share → Add to Home Screen flow.

## Sandbox capability

URL sandbox execution defaults to disabled. The runtime now has a durable encrypted-target queue, an isolated Playwright worker image, a disposable Chromium container per job, and a mitmproxy egress filter that validates and pins public DNS results at each upstream connection. The browser container has one Docker internal network only, no host mounts, no credentials, a read-only root filesystem, resource limits, dropped capabilities, and `no-new-privileges`. The existing ordinary URL scanner remains a separate feature. File analysis and detonation are unavailable.

Before enabling execution, build and start the sandbox images from the repository root:

```powershell
docker compose -f backend/sandbox/compose.yml up --build -d egress-proxy
docker compose -f backend/sandbox/compose.yml --profile build-only build browser-image
```

Run the host-gateway, direct-egress, direct-DNS, proxy-egress, and network-attachment checks from `backend/`:

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\verify_sandbox_network.py
```

The command must report `PASS` for every check. If any check fails or cannot run, leave `SANDBOX_NETWORK_VERIFIED=false` and `SANDBOX_RUNTIME_ENABLED=false`; URL submissions will fail closed. Never set the network verification flag based only on Docker being available.

The new `sandbox_jobs` table requires the checked-in Alembic migration. After positively verifying that the configured database is the intended local development database, a developer may apply it manually from `backend/` with `.\.venv\Scripts\python.exe -m alembic upgrade head`; the application and worker do not run migrations automatically. No migration was applied as part of this change.

Set a private `SANDBOX_ENCRYPTION_KEY` in `backend/.env`; generate a Fernet key locally with `.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. The API stores the queued target encrypted and clears it when the job ends. Keep the same key for the API and worker. Only after every network verification check passes should `SANDBOX_NETWORK_VERIFIED` and `SANDBOX_RUNTIME_ENABLED` be set to `true` in both processes.

Start the API and worker in separate PowerShell terminals, both from `backend/` and with the same environment:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

```powershell
.\.venv\Scripts\python.exe -m app.sandbox.worker
```

The worker uses a PostgreSQL advisory lock so only one supervisor is active. A job is stored only when scan-history persistence is enabled; otherwise the API returns `409` and does not queue the URL. Job data is linked to the normal scan record and follows its deletion cascade. This repository does not currently run an automatic 90-day purge, so retention still needs a separately reviewed cleanup process. Reports omit page text, cookies, credentials, full paths/query strings, and screenshots; forms and downloads are observed but never submitted or opened.

Playwright and mitmproxy image versions are pinned in the Dockerfiles. The network-verification and harmless browser test results must be confirmed on the target Docker Desktop machine before enabling this capability; the UI and API remain fail-closed until then.

## Scope notes

The backend provides the scan and account APIs used by the frontend; `/docs` lists the routes available in the running application. Configuration includes optional external-service API key settings, but this local setup does not configure or claim any external threat-intelligence integration. The setup steps above cover local development only, not production deployment.
