import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional

from src.domain.models import ApiKey
from src.ports.repositories import IApiKeyRepository
from src.adapters.postgresql.connection import PostgresConnection
from src.infrastructure.config import settings


def hash_api_key(raw_key: str, salt: str = "") -> str:
    salt = salt or settings.api_key_salt
    key = hashlib.pbkdf2_hmac(
        'sha256',
        raw_key.encode('utf-8'),
        salt.encode('utf-8'),
        600000,
        dklen=32,
    )
    return key.hex()


class PostgresApiKeyRepository(IApiKeyRepository):
    def get_by_hash(self, key_hash: str) -> Optional[ApiKey]:
        conn = PostgresConnection.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT key_hash, key_prefix, nombre_cliente, fecha_expiracion, "
                "activa, permisos, ultimo_uso FROM api_keys WHERE key_hash = %s",
                (key_hash,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return ApiKey(
                key_hash=row[0],
                key_prefix=row[1],
                nombre_cliente=row[2],
                fecha_expiracion=row[3],
                activa=row[4],
                permisos=row[5],
                ultimo_uso=row[6],
            )
        finally:
            conn.close()

    def store(self, api_key: ApiKey) -> None:
        conn = PostgresConnection.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO api_keys "
                "(key_hash, key_prefix, nombre_cliente, fecha_expiracion, activa, permisos) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (api_key.key_hash, api_key.key_prefix, api_key.nombre_cliente,
                 api_key.fecha_expiracion, api_key.activa, api_key.permisos),
            )
            conn.commit()
        finally:
            conn.close()

    def update_ultimo_uso(self, key_hash: str) -> None:
        conn = PostgresConnection.get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE api_keys SET ultimo_uso = NOW() WHERE key_hash = %s",
                (key_hash,),
            )
            conn.commit()
        finally:
            conn.close()
