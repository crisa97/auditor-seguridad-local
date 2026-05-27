import logging
from typing import Optional

import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.infrastructure.config import settings
from src.infrastructure.di import get_validar_api_key, get_validar_afirmacion
from src.application.validador import ResultadoValidacion

log = logging.getLogger("api.rag")
router = APIRouter()


class ConsultaRAG(BaseModel):
    texto: str = Field(..., min_length=1, max_length=10000,
                       description="Texto de la consulta")
    api_key: str = Field(..., min_length=1, description="API key para autenticacion")
    modelo: Optional[str] = Field(None, description="Modelo a usar (opcional)")


class RespuestaRAG(BaseModel):
    respuesta: str
    validaciones: list[dict] = []
    modelo_usado: str = ""
    advertencias: list[str] = []


@router.post("/consultar", response_model=RespuestaRAG)
def consultar_rag(body: ConsultaRAG, request: Request):
    client_ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for") or getattr(request.client, "host", "unknown")
    log.info("Consulta RAG recibida (texto length=%d, ip=%s)",
             len(body.texto), client_ip)

    validador_key = get_validar_api_key()
    es_valida, msg, datos_cliente = validador_key.execute(body.api_key)
    if not es_valida:
        log.warning("API key invalida: %s", msg)
        raise HTTPException(status_code=401, detail="API key invalida")

    permisos = (datos_cliente.get("permisos") or "").split(",")
    if "rag:leer" not in permisos and "rag:*" not in permisos:
        log.warning("API key sin permiso rag:leer - cliente: %s", datos_cliente.get("nombre_cliente"))
        raise HTTPException(status_code=403, detail="Permiso insuficiente")

    log.info("API key valida - cliente: %s", datos_cliente.get("nombre_cliente"))

    validador_afirmacion = get_validar_afirmacion()
    resultados_validacion = validador_afirmacion.validar_consulta(body.texto)
    advertencias = []

    if validador_afirmacion.hay_bloqueo(resultados_validacion):
        bloqueos = [r for r in resultados_validacion
                    if r.accion == ResultadoValidacion.BLOQUEAR]
        for b in bloqueos:
            advertencias.append(b.mensaje)
            log.warning("Afirmacion BLOQUEADA: '%s'", b.afirmacion[:80])

        return RespuestaRAG(
            respuesta="No puedo responder a esta consulta porque contiene "
                      "informacion identificada como falsos positivos.",
            validaciones=[r.__dict__ for r in resultados_validacion],
            advertencias=advertencias,
        )

    pendientes = [r for r in resultados_validacion
                  if r.accion == ResultadoValidacion.PENDIENTE]
    for p in pendientes:
        log.info("Afirmacion registrada como pendiente: '%s'", p.afirmacion[:80])

    modelo = body.modelo or settings.analyzer_model
    try:
        payload = {
            "model": modelo,
            "prompt": body.texto,
            "stream": False,
            "options": {
                "num_ctx": settings.llm_num_ctx,
                "temperature": settings.llm_temperature,
            },
        }
        r = requests.post(
            f"{settings.ollama_api_url}/generate",
            json=payload,
            timeout=settings.ollama_timeout,
        )
        r.raise_for_status()
        respuesta = r.json().get("response", "")
    except requests.Timeout:
        log.error("Timeout al consultar Ollama (modelo=%s)", modelo)
        raise HTTPException(status_code=504, detail="El modelo no respondio a tiempo")
    except requests.RequestException as e:
        log.error("Error al consultar Ollama: %s", e)
        raise HTTPException(status_code=502, detail="Error de comunicacion con el modelo")
    except (KeyError, ValueError) as e:
        log.error("Error al parsear respuesta de Ollama: %s", e)
        raise HTTPException(status_code=502, detail="Respuesta invalida del modelo")

    return RespuestaRAG(
        respuesta=respuesta,
        validaciones=[r.__dict__ for r in resultados_validacion],
        modelo_usado=modelo,
        advertencias=advertencias,
    )
