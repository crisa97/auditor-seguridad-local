import psycopg2
from psycopg2 import extensions

from src.infrastructure.config import settings


class PostgresConnection:
    @staticmethod
    def get_conn() -> extensions.connection:
        conn = psycopg2.connect(settings.db_url)
        conn.autocommit = False
        return conn
