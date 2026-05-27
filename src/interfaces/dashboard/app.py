import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.interfaces.dashboard.routers.dashboard import router as dashboard_router
from src.interfaces.dashboard.routers.apikeys import router as apikeys_router
from src.interfaces.dashboard.auth import router as auth_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("dashboard_service")

app = FastAPI(
    title="Dashboard Service - Seguridad Local",
    version="1.0.0",
    docs_url="/api/v2/docs",
)

_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,https://seguridad.local")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/v2/auth")
app.include_router(dashboard_router, prefix="/api/v2/dashboard")
app.include_router(apikeys_router, prefix="/api/v2")

_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/dashboard", StaticFiles(directory=_static_dir, html=True), name="dashboard_static")


@app.get("/api/v2/health")
def health():
    return {"status": "ok", "service": "dashboard-service"}


@app.on_event("startup")
def startup_event():
    log.info("=" * 50)
    log.info("  Dashboard Service iniciado")
    log.info("  Endpoints:")
    log.info("    POST /api/v2/auth/login")
    log.info("    POST /api/v2/auth/register")
    log.info("    GET  /api/v2/dashboard/stats")
    log.info("    GET  /api/v2/dashboard/analisis")
    log.info("    GET  /api/v2/dashboard/hallazgos")
    log.info("    GET  /api/v2/dashboard/vulnerabilidades")
    log.info("    POST /api/v2/apikeys")
    log.info("    GET  /api/v2/health")
    log.info("=" * 50)
