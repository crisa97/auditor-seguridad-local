import asyncio
import hashlib
import json
import logging
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validador import (
    validar_api_key, validar_consulta, hay_bloqueo,
    ResultadoValidacion, registrar_pendiente,
)
from config import API_KEY_SALT

log = logging.getLogger("openwebui_middleware")


def _redact(value: str, max_len: int = 8) -> str:
    h = hashlib.pbkdf2_hmac(
        'sha256',
        value.encode(),
        salt=b'redact_salt',
        iterations=100000,
        dklen=16,
    )
    return f"pbkdf2:{h.hex()[:max_len]}..."

ENRICH_URL = os.getenv("ENRICH_URL", "http://validation-service:8000/api/v1/rag/enrichir")
ENRICH_TIMEOUT = int(os.getenv("ENRICH_TIMEOUT", "120"))
ENRICH_INTERNAL_TOKEN = os.getenv("ENRICH_INTERNAL_TOKEN", "")

API_KEY_HEADER = "X-API-Key"

_middleware_active = False


def is_active():
    return _middleware_active


def activate():
    global _middleware_active
    _middleware_active = True
    log.debug("Middleware de validacion activado.")


def deactivate():
    global _middleware_active
    _middleware_active = False
    log.debug("Middleware de validacion desactivado.")


async def _fetch_rag_context(texto: str, api_key: str) -> str | None:
    payload = json.dumps({
        "texto": texto,
        "api_key": api_key,
        "max_cves": int(os.getenv("RAG_MAX_CVES", "5")),
        "max_exploits": int(os.getenv("RAG_MAX_EXPLOITS", "5")),
        "max_owasp": int(os.getenv("RAG_MAX_OWASP", "3")),
    }).encode()
    req = urllib.request.Request(
        ENRICH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=ENRICH_TIMEOUT)
        )
        data = json.loads(resp.read().decode())
        contexto = data.get("contexto", "")
        if contexto:
            log.debug("RAG enrichment: %d CVEs, %d Exploits, %d OWASP", data.get("total_cves", 0), data.get("total_exploits", 0), data.get("total_owasp", 0))
            return contexto
    except urllib.error.HTTPError as e:
        if e.code == 502:
            log.warning("RAG enrich: servicios vectoriales no disponibles")
        else:
            log.warning("RAG enrich: HTTP %d", e.code)
    except Exception:
        log.warning("RAG enrich error (detalle omitido)")
    return None


async def validation_middleware(request, call_next):
    if not _middleware_active:
        return await call_next(request)

    path = request.url.path

    if not any(p in path for p in ["/chat/completions", "/rag/consultar"]):
        return await call_next(request)

    # 1. Extraer API key (opcional para web UI, obligatoria para acceso externo)
    api_key = request.headers.get(API_KEY_HEADER) or ""

    # Solo validar la key si viene explicitamente (acceso externo)
    if api_key:
        es_valida, msg, datos = validar_api_key(api_key)
        if not es_valida:
            from starlette.responses import JSONResponse
            if datos and "nombre_cliente" in datos:
                log.warning("API key invalida para cliente: %s", _redact(datos["nombre_cliente"]))
            else:
                log.warning("API key invalida (no registrada)")
            return JSONResponse(status_code=401, content={"detail": msg})
    else:
        # Web UI: usar token interno para enrichment
        api_key = ENRICH_INTERNAL_TOKEN

    # 2. Extraer texto de la consulta
    try:
        body = await request.json()
        request._cached_body = body
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
            "No puedo procesar esta consulta porque contiene informacion "
            "identificada como falsos positivos:\n" +
            "\n".join(f"  - {b.mensaje}" for b in bloqueos)
        )
        log.info("Consulta bloqueada por %d afirmaciones falsas", len(bloqueos))
        return JSONResponse(
            status_code=403,
            content={"detail": mensaje, "bloqueos": [b.__dict__ for b in bloqueos]},
        )

    for r in resultados:
        if r.accion == ResultadoValidacion.PENDIENTE:
            registrar_pendiente(r.afirmacion, texto_consulta)

    # 4. Enriquecer con contexto RAG
    if os.getenv("RAG_AUTO_ENRICH", "true").lower() == "true" and api_key:
        try:
            rag_contexto = await _fetch_rag_context(texto_consulta, api_key)
            if rag_contexto:
                messages = body.get("messages", [])
                insert_pos = 0
                for i, m in enumerate(messages):
                    if m.get("role") == "system":
                        insert_pos = i + 1
                    else:
                        break
                messages.insert(insert_pos, {
                    "role": "system",
                    "content": f"Contexto de vulnerabilidades relevantes:\n{rag_contexto}"
                })
                body["messages"] = messages
                request._body = json.dumps(body).encode()
                if hasattr(request, "_json"):
                    del request._json
        except Exception:
            log.warning("Error en enrichment RAG (continuando sin contexto)")

    return await call_next(request)


def patch_openwebui(app):
    from fastapi import FastAPI
    if not isinstance(app, FastAPI):
        log.error("El argumento no es una instancia de FastAPI")
        return False

    app.middleware("http")(validation_middleware)
    activate()
    log.info("Middleware de validacion inyectado en Open WebUI")
    return True
