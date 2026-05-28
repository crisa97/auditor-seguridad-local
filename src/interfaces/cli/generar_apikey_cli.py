#! /usr/bin/env python3
import argparse
import secrets
import sys
import logging
from datetime import datetime, timedelta, timezone

from src.infrastructure.config import settings
from src.adapters.postgresql.apikey_repository import hash_api_key, PostgresApiKeyRepository
from src.domain.models import ApiKey

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def generar_api_key() -> str:
    return secrets.token_urlsafe(32)


def main():
    parser = argparse.ArgumentParser(
        description="Genera y almacena API keys seguras para el analizador RAG."
    )
    parser.add_argument("--cliente", required=True, help="Nombre del cliente")
    parser.add_argument("--permisos", default="rag:leer",
                        help="Permisos (ej: 'rag:leer', 'rag:escribir')")
    parser.add_argument("--dias", type=int, default=365,
                        help="Dias de validez (default: 365)")
    parser.add_argument("--solo-generar", action="store_true",
                        help="Solo genera la key sin almacenar en BD")
    args = parser.parse_args()

    raw_key = generar_api_key()
    key_hash = hash_api_key(raw_key)

    print(f"\n{'=' * 60}")
    print(f"  API Key generada")
    print(f"{'=' * 60}")
    print(f"  Cliente:       {args.cliente}")
    print(f"  Permisos:      {args.permisos}")
    print(f"  Expira en:     {args.dias} dias")
    print(f"  Longitud:      {len(raw_key)} caracteres")
    print()
    print(f"  La siguiente clave se muestra SOLO UNA VEZ. Guardela segura:")
    print(f"  [{'=' * 48}]")
    print(f"  | {raw_key:<46} |")
    print(f"  [{'=' * 48}]")
    print(f"  Hash (BD):     {key_hash[:16]}...")
    print(f"{'=' * 60}")
    print()

    key_prefix = raw_key[:8]
    raw_key = None

    if not args.solo_generar:
        repo = PostgresApiKeyRepository()
        api_key = ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            nombre_cliente=args.cliente,
            permisos=args.permisos,
            fecha_expiracion=datetime.now(timezone.utc) + timedelta(days=args.dias),
        )
        try:
            repo.store(api_key)
            log.info("API key almacenada para '%s' (expira: %s)", args.cliente,
                     api_key.fecha_expiracion.date())
        except Exception:
            sys.stderr.write("Error: No se pudo almacenar la API key en la base de datos.\n")
            sys.exit(1)
    else:
        print("(Modo solo-generar: la key NO se almaceno en la BD.)")
        print(f"Hash completo para insercion manual: {key_hash}")


if __name__ == "__main__":
    main()
