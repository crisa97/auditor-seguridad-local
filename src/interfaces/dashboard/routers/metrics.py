import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request

from src.adapters.mongodb.connection import MongoConnection
from src.interfaces.dashboard.middleware import require_auth

log = logging.getLogger("dashboard.routers.metrics")
router = APIRouter()


class TimelineItem:
    def __init__(self, fecha: str, analisis: int, hallazgos: int):
        self.fecha = fecha
        self.analisis = analisis
        self.hallazgos = hallazgos

    def dict(self):
        return {"fecha": self.fecha, "analisis": self.analisis, "hallazgos": self.hallazgos}


class TopVulnerabilidadItem:
    def __init__(self, cve_cwe: str, count: int, severidad: str):
        self.cve_cwe = cve_cwe
        self.count = count
        self.severidad = severidad

    def dict(self):
        return {"cve_cwe": self.cve_cwe, "count": self.count, "severidad": self.severidad}


@router.get("/stats/timeline")
@require_auth(roles=["admin"])
def get_timeline(request: Request):
    db = MongoConnection.get_db()
    try:
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)

        analisis_pipeline = [
            {"$match": {"timestamp": {"$gte": thirty_days_ago}}},
            {
                "$group": {
                    "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        analisis_data = {r["_id"]: r["count"] for r in db["analisis"].aggregate(analisis_pipeline)}

        hallazgos_pipeline = [
            {
                "$lookup": {
                    "from": "analisis",
                    "localField": "analisisId",
                    "foreignField": "_id",
                    "as": "analisis_info",
                }
            },
            {"$unwind": "$analisis_info"},
            {"$match": {"analisis_info.timestamp": {"$gte": thirty_days_ago}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$analisis_info.timestamp",
                        }
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        hallazgos_data = {r["_id"]: r["count"] for r in db["hallazgos"].aggregate(hallazgos_pipeline)}

        result = []
        current = thirty_days_ago
        while current <= now:
            fecha_str = current.strftime("%Y-%m-%d")
            result.append(
                {
                    "fecha": fecha_str,
                    "analisis": analisis_data.get(fecha_str, 0),
                    "hallazgos": hallazgos_data.get(fecha_str, 0),
                }
            )
            current += timedelta(days=1)

        return result
    except Exception as e:
        log.error("Error al obtener timeline: %s", e)
        raise HTTPException(status_code=500, detail="Error al obtener timeline")


@router.get("/stats/top-vulnerabilidades")
@require_auth(roles=["admin"])
def get_top_vulnerabilities(request: Request):
    db = MongoConnection.get_db()
    try:
        pipeline = [
            {"$match": {"cve_cwe": {"$ne": "N/A", "$exists": True, "$ne": ""}}},
            {"$group": {"_id": "$cve_cwe", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 15},
        ]
        raw = list(db["hallazgos"].aggregate(pipeline))

        result = []
        for item in raw:
            severidad_doc = db["hallazgos"].find_one(
                {"cve_cwe": item["_id"]}, {"severidad": 1, "_id": 0}
            )
            result.append(
                {
                    "cve_cwe": item["_id"],
                    "count": item["count"],
                    "severidad": severidad_doc.get("severidad", "Media") if severidad_doc else "Media",
                }
            )

        return result
    except Exception as e:
        log.error("Error al obtener top vulnerabilidades: %s", e)
        raise HTTPException(status_code=500, detail="Error al obtener top vulnerabilidades")
