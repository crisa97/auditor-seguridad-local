from datetime import datetime, timezone
from bson.objectid import ObjectId
from typing import Optional

from src.domain.models import Hallazgo, Analisis
from src.domain.enums import EstadoAnalisis
from src.ports.repositories import IHallazgoRepository, IAnalisisRepository
from src.adapters.mongodb.connection import MongoConnection


class MongoHallazgoRepository(IHallazgoRepository):
    def __init__(self):
        self._col = MongoConnection.get_db()["hallazgos"]

    def store(self, hallazgo: Hallazgo) -> str:
        doc = {
            "analisisId": hallazgo.analisis_id,
            "filepath": hallazgo.filepath,
            "severidad": hallazgo.severidad,
            "titulo": hallazgo.titulo,
            "descripcion": hallazgo.descripcion,
            "mitigacion": hallazgo.mitigacion,
            "ubicacion": hallazgo.ubicacion,
            "cve_cwe": hallazgo.cve_cwe,
            "raw_response": hallazgo.raw_response,
        }
        result = self._col.insert_one(doc)
        return str(result.inserted_id)

    def get_by_analisis(self, analisis_id: str) -> list[Hallazgo]:
        docs = self._col.find({"analisisId": analisis_id})
        return [Hallazgo(
            analisis_id=d["analisisId"],
            filepath=d["filepath"],
            severidad=d["severidad"],
            titulo=d["titulo"],
            descripcion=d["descripcion"],
            mitigacion=d["mitigacion"],
            ubicacion=d["ubicacion"],
            cve_cwe=d["cve_cwe"],
            raw_response=d.get("raw_response", ""),
        ) for d in docs]

    def get_severidad_counts(self, analisis_id: str) -> dict[str, int]:
        pipeline = [
            {"$match": {"analisisId": analisis_id}},
            {"$group": {"_id": "$severidad", "count": {"$sum": 1}}},
        ]
        return {r["_id"]: r["count"] for r in self._col.aggregate(pipeline)}


class MongoAnalisisRepository(IAnalisisRepository):
    def __init__(self):
        self._col = MongoConnection.get_db()["analisis"]

    def create(self, project_path: str, total_files: int = 0) -> str:
        doc = {
            "projectPath": project_path,
            "timestamp": datetime.now(timezone.utc),
            "estado": EstadoAnalisis.PENDIENTE,
            "totalFiles": total_files,
            "archivosAnalizados": 0,
            "taskId": "",
        }
        result = self._col.insert_one(doc)
        return str(result.inserted_id)

    def update_state(self, analisis_id: str, estado: str, **kwargs) -> None:
        update = {"$set": {"estado": estado, **kwargs}}
        self._col.update_one({"_id": ObjectId(analisis_id)}, update)

    def get_by_id(self, analisis_id: str) -> Optional[Analisis]:
        doc = self._col.find_one({"_id": ObjectId(analisis_id)})
        if doc is None:
            return None
        return Analisis(
            id=str(doc["_id"]),
            project_path=doc.get("projectPath", ""),
            timestamp=doc.get("timestamp", datetime.now()),
            estado=doc.get("estado", ""),
            total_files=doc.get("totalFiles", 0),
            archivos_analizados=doc.get("archivosAnalizados", 0),
            task_id=doc.get("taskId", ""),
            reporte_txt=doc.get("reporteTxt", ""),
            reporte_pdf=doc.get("reportePdf", ""),
            error=doc.get("error", ""),
        )

    def list_all(self, limit: int = 20) -> list[Analisis]:
        docs = self._col.find().sort("timestamp", -1).limit(limit)
        return [Analisis(
            id=str(d["_id"]),
            project_path=d.get("projectPath", ""),
            timestamp=d.get("timestamp", datetime.now()),
            estado=d.get("estado", ""),
            total_files=d.get("totalFiles", 0),
            archivos_analizados=d.get("archivosAnalizados", 0),
            task_id=d.get("taskId", ""),
            reporte_txt=d.get("reporteTxt", ""),
            reporte_pdf=d.get("reportePdf", ""),
            error=d.get("error", ""),
        ) for d in docs]
