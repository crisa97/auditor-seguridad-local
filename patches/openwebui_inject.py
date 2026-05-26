"""
openwebui_inject.py — Parche para inyectar el middleware de validación
en el backend de Open WebUI.

Este script se ejecuta durante el arranque de Open WebUI (entrypoint personalizado).
Parchea el router de FastAPI para interceptar las consultas antes de que lleguen al LLM.

Uso en Dockerfile:
  COPY patches/openwebui_inject.py /app/backend/openwebui_inject.py
  CMD ["python", "-c", "import openwebui_inject; from open_webui.main import app; ..."]
"""
import logging
import os
import sys

# Asegurar que el directorio raíz está en sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validador import (
    validar_api_key, validar_consulta, hay_bloqueo,
    ResultadoValidacion, registrar_pendiente,
)
from config import API_KEY_SALT

log = logging.getLogger("openwebui_middleware")

# ── Headers que Open WebUI busca en cada request ──────────────────────────
API_KEY_HEADER = "X-API-Key"

# ── Almacén de estado para el middleware ──────────────────────────────────
_middleware_active = False


def is_active():
    return _middleware_active


def activate():
    """Activa el middleware de validación en Open WebUI."""
    global _middleware_active
    _middleware_active = True
    log.info("🔐 Middleware de validación activado.")


def deactivate():
    global _middleware_active
    _middleware_active = False
    log.info("🔓 Middleware de validación desactivado.")


# ── Función middleware para FastAPI ────────────────────────────────────────

async def validation_middleware(request, call_next):
    """
    Middleware ASGI que intercepta peticiones a /api/chat/completions
    y /api/v1/rag/consultar para validar API key y conocimiento.
    """
    if not _middleware_active:
        return await call_next(request)

    path = request.url.path

    # Solo interceptar endpoints de chat/consulta
    if not any(p in path for p in ["/chat/completions", "/rag/consultar"]):
        return await call_next(request)

    # 1. Validar API key
    api_key = request.headers.get(API_KEY_HEADER) or ""
    if not api_key:
        from starlette.responses import JSONResponse
        return JSONResponse(
            status_code=401,
            content={"detail": "API key requerida (header X-API-Key)"},
        )

    es_valida, msg, datos = validar_api_key(api_key)
    if not es_valida:
        from starlette.responses import JSONResponse
        log.warning("API key inválida: %s", msg)
        return JSONResponse(
            status_code=401,
            content={"detail": msg},
        )

    # 2. Extraer texto de la consulta
    try:
        body = await request.json()
        texto_consulta = body.get("messages", [{}])[-1].get("content", "") or \
                         body.get("prompt", "") or \
                         body.get("texto", "")
    except Exception:
        texto_consulta = ""

    if not texto_consulta:
        return await call_next(request)

    # 3. Validar afirmaciones
    resultados = validar_consulta(texto_consulta)
    if hay_bloqueo(resultados):
        from starlette.responses import JSONResponse
        bloqueos = [r for r in resultados
                    if r.accion == ResultadoValidacion.BLOQUEAR]
        mensaje = (
            "No puedo procesar esta consulta porque contiene información "
            "identificada como falsos positivos:\n" +
            "\n".join(f"  - {b.mensaje}" for b in bloqueos)
        )
        log.warning("Consulta bloqueada por %d afirmaciones falsas", len(bloqueos))
        return JSONResponse(
            status_code=403,
            content={"detail": mensaje, "bloqueos": [b.__dict__ for b in bloqueos]},
        )

    # 4. Registrar pendientes
    for r in resultados:
        if r.accion == ResultadoValidacion.PENDIENTE:
            registrar_pendiente(r.afirmacion, texto_consulta)

    return await call_next(request)


# ── Parche para el app de FastAPI ──────────────────────────────────────────

def patch_openwebui(app):
    """
    Inyecta el middleware de validación en la aplicación FastAPI de Open WebUI.
    Llámala justo después de crear la app, antes de arrancar el servidor.
    """
    from fastapi import FastAPI
    if not isinstance(app, FastAPI):
        log.error("El argumento no es una instancia de FastAPI")
        return False

    app.middleware("http")(validation_middleware)
    activate()
    log.info("✅ Middleware de validación inyectado en Open WebUI")
    return True
