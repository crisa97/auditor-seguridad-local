from pymongo import UpdateOne

from src.domain.models import OwaspTop10Entry
from src.ports.repositories import IOwaspTop10Repository
from src.adapters.mongodb.connection import MongoConnection


class MongoOwaspTop10Repository(IOwaspTop10Repository):
    def __init__(self):
        self._col = MongoConnection.get_db()["owasp_top10"]

    def store(self, entry: OwaspTop10Entry) -> None:
        self._col.update_one(
            {"id": entry.id},
            {"$set": {
                "id": entry.id,
                "category": entry.category,
                "title": entry.title,
                "content": entry.content,
                "risk_rank": entry.risk_rank,
                "cwes": entry.cwes,
                "chromaId": entry.chroma_id,
            }},
            upsert=True,
        )

    def store_bulk(self, entries: list[OwaspTop10Entry]) -> int:
        if not entries:
            return 0
        operations = [
            UpdateOne({"id": e.id}, {"$set": {
                "id": e.id,
                "category": e.category,
                "title": e.title,
                "content": e.content,
                "risk_rank": e.risk_rank,
                "cwes": e.cwes,
                "chromaId": e.chroma_id,
            }}, upsert=True)
            for e in entries
        ]
        self._col.bulk_write(operations)
        return len(entries)

    def get_all_ids(self) -> list[str]:
        return [doc["id"] for doc in self._col.find({}, {"id": 1})]

    def get_by_chroma_ids(self, chroma_ids: list[str]) -> list[OwaspTop10Entry]:
        docs = self._col.find({"chromaId": {"$in": chroma_ids}})
        return [
            OwaspTop10Entry(
                id=d["id"],
                category=d.get("category", ""),
                title=d.get("title", ""),
                content=d.get("content", ""),
                risk_rank=d.get("risk_rank", ""),
                cwes=d.get("cwes", ""),
                chroma_id=d.get("chromaId", ""),
            )
            for d in docs
        ]