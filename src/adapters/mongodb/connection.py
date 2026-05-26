from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from src.infrastructure.config import settings


class MongoConnection:
    _instance: MongoClient | None = None

    @classmethod
    def get_client(cls) -> MongoClient:
        if cls._instance is None:
            cls._instance = MongoClient(
                settings.mongo_uri,
                serverSelectionTimeoutMS=settings.mongo_timeout_ms,
            )
        return cls._instance

    @classmethod
    def get_db(cls):
        return cls.get_client()[settings.mongo_database]

    @classmethod
    def ping(cls) -> bool:
        try:
            cls.get_client().admin.command('ping')
            return True
        except ConnectionFailure:
            return False

    @classmethod
    def reset(cls) -> None:
        if cls._instance:
            cls._instance.close()
            cls._instance = None
