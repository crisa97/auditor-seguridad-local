import logging
from typing import Optional

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from src.infrastructure.config import settings
from src.infrastructure.di import get_validar_api_key, get_validar_afirmacion, get_analizador, get_analisis_repository
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


# ─── Remote Analysis Endpoint (v2) ────────────────────────────────────────

class ArchivoAnalisis(BaseModel):
    filepath: str = Field(..., min_length=1, max_length=500,
                          description="Ruta relativa del archivo dentro del proyecto")
    contenido: str = Field(..., min_length=1,
                           description="Contenido completo del archivo")


class AnalizarRequest(BaseModel):
    api_key: str = Field(..., min_length=1, description="API key con permiso rag:analizar")
    nombre_proyecto: str = Field(..., min_length=1, max_length=255,
                                 description="Nombre o ruta del proyecto")
    archivos: list[ArchivoAnalisis] = Field(..., min_length=1, max_length=500,
                                            description="Archivos a analizar")


class HallazgoResumen(BaseModel):
    filepath: str
    severidad: str
    titulo: str
    ubicacion: str = ""


class AnalizarResponse(BaseModel):
    analisis_id: str
    status: str
    total_archivos: int
    total_hallazgos: int
    hallazgos: list[HallazgoResumen] = []
    pdf_url: str = ""


@router.post("/analizar", response_model=AnalizarResponse)
def analizar_proyecto_remoto(body: AnalizarRequest, request: Request):
    client_ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for") or getattr(request.client, "host", "unknown")
    log.info("Analisis remoto recibido (proyecto=%s, archivos=%d, ip=%s)",
             body.nombre_proyecto, len(body.archivos), client_ip)

    # 1. Validar API key
    validador_key = get_validar_api_key()
    es_valida, msg, datos_cliente = validador_key.execute(body.api_key)
    if not es_valida:
        log.warning("API key invalida: %s", msg)
        raise HTTPException(status_code=401, detail="API key invalida")

    permisos = (datos_cliente.get("permisos") or "").split(",")
    if "rag:analizar" not in permisos and "rag:*" not in permisos:
        log.warning("API key sin permiso rag:analizar - cliente: %s", datos_cliente.get("nombre_cliente"))
        raise HTTPException(status_code=403, detail="Permiso insuficiente")

    usuario_id = datos_cliente.get("usuario_id", 0)
    log.info("API key valida - cliente: %s, usuario_id: %s", datos_cliente.get("nombre_cliente"), usuario_id)

    # 2. Ejecutar pipeline de analisis
    analizador = get_analizador()
    archivos_list = [{"filepath": a.filepath, "contenido": a.contenido} for a in body.archivos]
    try:
        result = analizador.execute(
            project_path=body.nombre_proyecto,
            usuario_id=usuario_id,
            archivos_remotos=archivos_list,
        )
    except Exception as e:
        log.error("Error en analisis remoto: %s", e)
        raise HTTPException(status_code=500, detail=f"Error en el analisis: {str(e)}")

    if result.get("status") == "error":
        return AnalizarResponse(
            analisis_id=result.get("analisis_id", ""),
            status="error",
            total_archivos=0,
            total_hallazgos=0,
        )

    analisis_id = result["analisis_id"]

    # 3. Almacenar PDF en GridFS
    pdf_bytes = result.get("pdf_bytes")
    if pdf_bytes:
        analisis_repo = get_analisis_repository()
        analisis_repo.store_pdf(analisis_id, pdf_bytes)
        pdf_url = f"/api/v2/rag/reportes/{analisis_id}"
    else:
        pdf_url = ""

    # 4. Obtener hallazgos
    hallazgos_list: list[HallazgoResumen] = []
    try:
        from src.adapters.mongodb.hallazgo_repository import MongoHallazgoRepository
        repo = MongoHallazgoRepository()
        hallazgos = repo.get_by_analisis(analisis_id)
        hallazgos_list = [
            HallazgoResumen(
                filepath=h.filepath,
                severidad=h.severidad,
                titulo=h.titulo,
                ubicacion=h.ubicacion,
            )
            for h in hallazgos
        ]
    except Exception as e:
        log.warning("No se pudieron obtener hallazgos: %s", e)

    return AnalizarResponse(
        analisis_id=analisis_id,
        status="completado",
        total_archivos=result.get("total_files", 0),
        total_hallazgos=result.get("total_vulnerabilidades", 0),
        hallazgos=hallazgos_list,
        pdf_url=pdf_url,
    )


@router.get("/reportes/{analisis_id}")
def ver_reporte(analisis_id: str, download: bool = False):
    analisis_repo = get_analisis_repository()
    pdf_bytes = analisis_repo.get_pdf(analisis_id)
    if pdf_bytes is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    disposition = "attachment" if download else "inline"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"{disposition}; filename=reporte_{analisis_id}.pdf"},
    )
