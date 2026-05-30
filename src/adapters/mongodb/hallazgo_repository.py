from datetime import datetime, timezone
from bson.objectid import ObjectId
from gridfs import GridFS
from gridfs.errors import NoFile
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
            "owasp": hallazgo.owasp,
            "raw_response": hallazgo.raw_response,
            "usuarioId": hallazgo.usuario_id,
        }
        result = self._col.insert_one(doc)
        return str(result.inserted_id)

    def get_by_analisis(self, analisis_id: str) -> list[Hallazgo]:
        docs = self._col.find({"analisisId": analisis_id})
        return [Hallazgo(
            analisis_id=d.get("analisisId", ""),
            filepath=d.get("filepath", ""),
            severidad=d.get("severidad", "Media"),
            titulo=d.get("titulo", ""),
            descripcion=d.get("descripcion", ""),
            mitigacion=d.get("mitigacion", ""),
            ubicacion=d.get("ubicacion", ""),
            cve_cwe=d.get("cve_cwe", "N/A"),
            owasp=d.get("owasp", ""),
            raw_response=d.get("raw_response", ""),
            usuario_id=d.get("usuarioId", 0),
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
        self._fs = GridFS(MongoConnection.get_db())

    def create(self, project_path: str, total_files: int = 0, usuario_id: int = 0) -> str:
        doc = {
            "projectPath": project_path,
            "timestamp": datetime.now(timezone.utc),
            "estado": EstadoAnalisis.PENDIENTE,
            "totalFiles": total_files,
            "archivosAnalizados": 0,
            "taskId": "",
            "usuarioId": usuario_id,
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
            usuario_id=doc.get("usuarioId", 0),
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
            usuario_id=d.get("usuarioId", 0),
        ) for d in docs]

    def store_pdf(self, analisis_id: str, pdf_bytes: bytes) -> None:
        try:
            existing = self._fs.find_one({"filename": f"reporte_{analisis_id}.pdf"})
            if existing:
                self._fs.delete(existing._id)
            self._fs.put(pdf_bytes, filename=f"reporte_{analisis_id}.pdf", metadata={"analisisId": analisis_id})
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Error al almacenar PDF en GridFS: %s", e)

    def get_pdf(self, analisis_id: str) -> Optional[bytes]:
        try:
            gf = self._fs.find_one({"filename": f"reporte_{analisis_id}.pdf"})
            if gf is None:
                return None
            return gf.read()
        except NoFile:
            return None
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Error al leer PDF de GridFS: %s", e)
            return None
