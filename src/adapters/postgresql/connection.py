import logging

import psycopg2
from psycopg2 import extensions, pool

from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


class PostgresConnection:
    _pool: pool.SimpleConnectionPool | None = None

    @classmethod
    def _get_pool(cls) -> pool.SimpleConnectionPool:
        if cls._pool is None:
            cls._pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=10,
                dsn=settings.db_url,
            )
            logger.info("PostgreSQL connection pool created (min=1, max=10)")
        return cls._pool

    @classmethod
    def get_conn(cls) -> extensions.connection:
        conn = cls._get_pool().getconn()
        conn.autocommit = False
        return conn

    @classmethod
    def return_conn(cls, conn: extensions.connection) -> None:
        if cls._pool is not None:
            cls._pool.putconn(conn)
        else:
            conn.close()

    @classmethod
    def close_all(cls) -> None:
        if cls._pool is not None:
            cls._pool.closeall()
            cls._pool = None
            logger.info("PostgreSQL connection pool closed")
