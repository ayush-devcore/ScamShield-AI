from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.routes.dashboard import router as dashboard_router
from app.routes.reports import router as reports_router
from app.core.config import settings
from app.routes.auth import router as auth_router
from app.routes.health import router as health_router
from app.routes.scans import router as scans_router
from app.routes.activity import router as activity_router
from app.routes.preferences import router as preferences_router
from app.routes.notifications import router as notifications_router
from app.routes.sandbox import router as sandbox_router

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.exception_handler(RequestValidationError)
async def safe_password_recovery_validation_error(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/v1/auth/password-reset/authenticator":
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid password recovery request."},
        )
    if request.url.path.startswith("/api/v1/sandbox/"):
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid sandbox request."},
        )
    return await request_validation_exception_handler(request, exc)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


app.include_router(
    health_router,
    prefix="/api/v1",
)
app.include_router(
    auth_router,
    prefix="/api/v1",
)
app.include_router(
    dashboard_router,
    prefix="/api/v1",
)
app.include_router(
    reports_router,
    prefix="/api/v1",
)
app.include_router(
    scans_router,
    prefix="/api/v1",
)
app.include_router(activity_router, prefix="/api/v1")
app.include_router(preferences_router, prefix="/api/v1")
app.include_router(notifications_router, prefix="/api/v1")
app.include_router(sandbox_router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "message": "API online",
    }
