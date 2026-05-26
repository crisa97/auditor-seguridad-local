#! /usr/bin/env python3
"""
Wrapper backward-compatible.
"""
from src.interfaces.cli.generar_apikey_cli import main, generar_api_key
from src.adapters.postgresql.apikey_repository import hash_api_key, PostgresApiKeyRepository
from src.domain.models import ApiKey
from datetime import datetime, timedelta, timezone


def almacenar_api_key(raw_key: str, nombre_cliente: str,
                       permisos: str = "rag:leer",
                       dias_validez: int = 365) -> bool:
    key_hash = hash_api_key(raw_key)
    key_prefix = raw_key[:8]
    expiracion = datetime.now(timezone.utc) + timedelta(days=dias_validez)
    try:
        repo = PostgresApiKeyRepository()
        repo.store(ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            nombre_cliente=nombre_cliente,
            permisos=permisos,
            fecha_expiracion=expiracion,
        ))
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
