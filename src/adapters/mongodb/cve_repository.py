from typing import Optional

from src.domain.models import Cve, Exploit
from src.ports.repositories import ICveRepository, IExploitRepository
from src.adapters.mongodb.connection import MongoConnection


class MongoCveRepository(ICveRepository):
    def __init__(self):
        self._col = MongoConnection.get_db()["cves"]

    def get_by_id(self, cve_id: str) -> Optional[Cve]:
        doc = self._col.find_one({"id": cve_id})
        if doc is None:
            return None
        return Cve(
            id=doc["id"],
            description=doc.get("description", ""),
            severity=doc.get("severity", "N/A"),
            score=doc.get("score", "N/A"),
            chroma_id=doc.get("chromaId", ""),
        )

    def store(self, cve: Cve) -> None:
        self._col.update_one(
            {"id": cve.id},
            {"$set": {
                "id": cve.id,
                "description": cve.description,
                "severity": cve.severity,
                "score": cve.score,
                "chromaId": cve.chroma_id,
            }},
            upsert=True,
        )

    def store_bulk(self, cves: list[Cve]) -> int:
        for cve in cves:
            self._col.update_one({"id": cve.id}, {"$set": {
                "id": cve.id,
                "description": cve.description,
                "severity": cve.severity,
                "score": cve.score,
                "chromaId": cve.chroma_id,
            }}, upsert=True)
        return len(cves)

    def get_all_ids(self) -> list[str]:
        return [doc["id"] for doc in self._col.find({}, {"id": 1})]

    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[Cve]:
        docs = self._col.find({"chromaId": {"$in": chroma_ids}})
        return [
            Cve(
                id=d["id"],
                description=d.get("description", ""),
                severity=d.get("severity", "N/A"),
                score=d.get("score", "N/A"),
                chroma_id=d.get("chromaId", ""),
            )
            for d in docs
        ]


class MongoExploitRepository(IExploitRepository):
    def __init__(self):
        self._col = MongoConnection.get_db()["exploits"]

    def store(self, exploit: Exploit) -> None:
        self._col.update_one(
            {"id": exploit.id},
            {"$set": {
                "id": exploit.id,
                "path": exploit.path,
                "text": exploit.text,
                "chromaId": exploit.chroma_id,
            }},
            upsert=True,
        )

    def store_bulk(self, exploits: list[Exploit]) -> int:
        for exp in exploits:
            self._col.update_one({"id": exp.id}, {"$set": {
                "id": exp.id,
                "path": exp.path,
                "text": exp.text,
                "chromaId": exp.chroma_id,
            }}, upsert=True)
        return len(exploits)

    def get_all_ids(self) -> list[str]:
        return [doc["id"] for doc in self._col.find({}, {"id": 1})]

    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[Exploit]:
        docs = self._col.find({"chromaId": {"$in": chroma_ids}})
        return [
            Exploit(
                id=d["id"],
                path=d.get("path", ""),
                text=d.get("text", ""),
                chroma_id=d.get("chromaId", ""),
            )
            for d in docs
        ]
