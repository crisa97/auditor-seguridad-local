import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from src.adapters.mongodb.connection import MongoConnection
from src.interfaces.dashboard.middleware import require_auth

log = logging.getLogger("dashboard.routers.dashboard")
router = APIRouter()


class StatItem(BaseModel):
    label: str
    value: int


class StatsResponse(BaseModel):
    total_analisis: int
    analisis_completados: int
    analisis_fallidos: int
    analisis_en_curso: int
    total_hallazgos: int
    hallazgos_por_severidad: dict[str, int]
    total_cves_indexadas: int
    total_exploits_indexados: int


class AnalisisItem(BaseModel):
    id: str
    projectPath: str
    timestamp: str
    estado: str
    totalFiles: int
    archivosAnalizados: int
    reportePdf: str = ""
    reporteTxt: str = ""
    error: str = ""


class HallazgoItem(BaseModel):
    analisisId: str
    filepath: str
    severidad: str
    titulo: str
    descripcion: str
    mitigacion: str
    ubicacion: str
    cve_cwe: str


class CveItem(BaseModel):
    id: str
    description: str
    severity: str
    score: str


def _build_usuario_filter(request: Request) -> dict:
    user = request.state.user
    if user.get("rol") == "admin":
        return {}
    return {"usuarioId": user.get("id", 0)}


@router.get("/stats", response_model=StatsResponse)
@require_auth(roles=["admin"])
def get_stats(request: Request):
    db = MongoConnection.get_db()
    try:
        total_analisis = db["analisis"].count_documents({})
        analisis_completados = db["analisis"].count_documents({"estado": "completado"})
        analisis_fallidos = db["analisis"].count_documents({"estado": "fallido"})
        analisis_en_curso = db["analisis"].count_documents({"estado": {"$in": ["pendiente", "en_proceso"]}})
        total_hallazgos = db["hallazgos"].count_documents({})

        severidad_pipeline = [
            {"$group": {"_id": "$severidad", "count": {"$sum": 1}}}
        ]
        severidad_raw = list(db["hallazgos"].aggregate(severidad_pipeline))
        hallazgos_por_severidad = {r["_id"]: r["count"] for r in severidad_raw}

        total_cves = db["cves"].count_documents({})
        total_exploits = db["exploits"].count_documents({})

        return StatsResponse(
            total_analisis=total_analisis,
            analisis_completados=analisis_completados,
            analisis_fallidos=analisis_fallidos,
            analisis_en_curso=analisis_en_curso,
            total_hallazgos=total_hallazgos,
            hallazgos_por_severidad=hallazgos_por_severidad,
            total_cves_indexadas=total_cves,
            total_exploits_indexados=total_exploits,
        )
    except Exception as e:
        log.error("Error al obtener estadisticas: %s", e)
        raise HTTPException(status_code=500, detail="Error al obtener estadisticas")


@router.get("/analisis")
@require_auth(roles=["admin", "usuario"])
def get_analisis(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    estado: Optional[str] = Query(default=None),
):
    db = MongoConnection.get_db()
    try:
        query = _build_usuario_filter(request)
        if estado:
            query["estado"] = estado
        docs = list(db["analisis"].find(query).sort("timestamp", -1).limit(limit))
        return [
            AnalisisItem(
                id=str(d["_id"]),
                projectPath=d.get("projectPath", ""),
                timestamp=str(d.get("timestamp", "")),
                estado=d.get("estado", ""),
                totalFiles=d.get("totalFiles", 0),
                archivosAnalizados=d.get("archivosAnalizados", 0),
                reportePdf=d.get("reportePdf", ""),
                reporteTxt=d.get("reporteTxt", ""),
                error=d.get("error", ""),
            )
            for d in docs
        ]
    except Exception as e:
        log.error("Error al listar analisis: %s", e)
        raise HTTPException(status_code=500, detail="Error al listar analisis")


@router.get("/hallazgos")
@require_auth(roles=["admin", "usuario"])
def get_hallazgos(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    severidad: Optional[str] = Query(default=None),
    analisis_id: Optional[str] = Query(default=None),
):
    db = MongoConnection.get_db()
    try:
        query = _build_usuario_filter(request)
        if severidad:
            query["severidad"] = severidad
        if analisis_id:
            query["analisisId"] = analisis_id
        docs = list(db["hallazgos"].find(query).sort("_id", -1).limit(limit))
        return [
            HallazgoItem(
                analisisId=d.get("analisisId", ""),
                filepath=d.get("filepath", ""),
                severidad=d.get("severidad", "Media"),
                titulo=d.get("titulo", ""),
                descripcion=d.get("descripcion", ""),
                mitigacion=d.get("mitigacion", ""),
                ubicacion=d.get("ubicacion", ""),
                cve_cwe=d.get("cve_cwe", "N/A"),
            )
            for d in docs
        ]
    except Exception as e:
        log.error("Error al listar hallazgos: %s", e)
        raise HTTPException(status_code=500, detail="Error al listar hallazgos")


@router.get("/vulnerabilidades")
@require_auth(roles=["admin"])
def get_vulnerabilidades(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
):
    db = MongoConnection.get_db()
    try:
        query = {}
        if severity:
            query["severity"] = severity.upper()
        docs = list(db["cves"].find(query).sort("_id", -1).limit(limit))
        return [
            CveItem(
                id=d.get("id", ""),
                description=d.get("description", "")[:300],
                severity=d.get("severity", "N/A"),
                score=d.get("score", "N/A"),
            )
            for d in docs
        ]
    except Exception as e:
        log.error("Error al listar vulnerabilidades: %s", e)
        raise HTTPException(status_code=500, detail="Error al listar vulnerabilidades")
