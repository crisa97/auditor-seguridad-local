import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.interfaces.dashboard.routers.dashboard import router as dashboard_router
from src.interfaces.dashboard.routers.apikeys import router as apikeys_router
from src.interfaces.dashboard.routers.users import router as users_router
from src.interfaces.dashboard.routers.metrics import router as metrics_router
from src.interfaces.dashboard.auth import router as auth_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("dashboard_service")

app = FastAPI(
    title="Dashboard Service - Seguridad Local",
    version="2.0.0",
    docs_url="/api/v2/docs",
)

_cors_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,https://seguridad.local",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/v2/auth")
app.include_router(dashboard_router, prefix="/api/v2/dashboard")
app.include_router(metrics_router, prefix="/api/v2/dashboard")
app.include_router(apikeys_router, prefix="/api/v2")
app.include_router(users_router, prefix="/api/v2")

_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/dashboard", StaticFiles(directory=_static_dir, html=True), name="dashboard_static")


@app.get("/api/v2/health")
def health():
    return {"status": "ok", "service": "dashboard-service"}


@app.on_event("startup")
def startup_event():
    log.info("=" * 60)
    log.info("  Dashboard Service v2.0.0 iniciado")
    log.info("  Endpoints:")
    log.info("    POST   /api/v2/auth/login")
    log.info("    POST   /api/v2/auth/register")
    log.info("    POST   /api/v2/auth/refresh")
    log.info("    GET    /api/v2/dashboard/stats")
    log.info("    GET    /api/v2/dashboard/analisis")
    log.info("    GET    /api/v2/dashboard/hallazgos")
    log.info("    GET    /api/v2/dashboard/vulnerabilidades")
    log.info("    GET    /api/v2/dashboard/stats/timeline")
    log.info("    GET    /api/v2/dashboard/stats/top-vulnerabilidades")
    log.info("    GET    /api/v2/apikeys")
    log.info("    POST   /api/v2/apikeys")
    log.info("    PUT    /api/v2/apikeys/{id}/toggle")
    log.info("    DELETE /api/v2/apikeys/{id}")
    log.info("    GET    /api/v2/users")
    log.info("    GET    /api/v2/users/me")
    log.info("    PUT    /api/v2/users/me")
    log.info("    POST   /api/v2/users/me/change-password")
    log.info("    POST   /api/v2/users")
    log.info("    GET    /api/v2/users/{id}")
    log.info("    PUT    /api/v2/users/{id}")
    log.info("    DELETE /api/v2/users/{id}")
    log.info("    POST   /api/v2/users/{id}/reset-password")
    log.info("    GET    /api/v2/health")
    log.info("=" * 60)
