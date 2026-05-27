"""
validation_api.py — Servicio FastAPI que actua como middleware de validacion
para Open WebUI.

Arquitectura:
  Cliente -> Nginx -> validation_service -> Open WebUI
                        |
                   PostgreSQL (api_keys + conocimiento_validado)
"""
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.interfaces.api.routers.rag import router as rag_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("validation_service")

app = FastAPI(
    title="Validation Service - Open WebUI Middleware",
    version="1.0.0",
    docs_url="/api/v1/docs",
)

_cors_origins = os.getenv("CORS_ORIGINS")
if not _cors_origins:
    log.warning("CORS_ORIGINS no configurado - permitiendo solo localhost:3000")
    _cors_origins = "http://localhost:3000"
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(rag_router, prefix="/api/v1/rag")


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "validation-service"}


@app.on_event("startup")
def startup_event():
    log.info("=" * 50)
    log.info("  Validation Service iniciado")
    log.info("  Endpoints:")
    log.info("    POST /api/v1/rag/consultar")
    log.info("    GET  /api/v1/health")
    log.info("    GET  /api/v1/docs")
    log.info("=" * 50)
