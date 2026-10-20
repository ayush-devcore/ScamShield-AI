from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.dashboard import router as dashboard_router
from app.routes.reports import router as reports_router
from app.core.config import settings
from app.routes.auth import router as auth_router
from app.routes.health import router as health_router
from app.routes.scans import router as scans_router

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


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


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "message": "API online",
    }