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

    prefix = raw_key[:8]
    sys.stdout.write(f"\n{'=' * 60}\n")
    sys.stdout.write(f"  API Key generada\n")
    sys.stdout.write(f"{'=' * 60}\n")
    sys.stdout.write(f"  Cliente:       {args.cliente}\n")
    sys.stdout.write(f"  Permisos:      {args.permisos}\n")
    sys.stdout.write(f"  Expira en:     {args.dias} dias\n")
    sys.stdout.write(f"  Prefix (id):   {prefix}...\n")
    sys.stdout.write("\n")
    sys.stdout.write(f"  La siguiente clave se muestra SOLO UNA VEZ. Guardala segura:\n")
    sys.stdout.write(f"  [{'=' * 48}]\n")
    sys.stdout.write(f"  | {raw_key:<46} |\n")
    sys.stdout.write(f"  [{'=' * 48}]\n")
    sys.stdout.write(f"  Hash (BD):     {key_hash[:16]}...\n")
    sys.stdout.write(f"{'=' * 60}\n\n")
    sys.stdout.flush()

    if not args.solo_generar:
        repo = PostgresApiKeyRepository()
        api_key = ApiKey(
            key_hash=key_hash,
            key_prefix=prefix,
            nombre_cliente=args.cliente,
            permisos=args.permisos,
            fecha_expiracion=datetime.now(timezone.utc) + timedelta(days=args.dias),
        )
        try:
            repo.store(api_key)
            log.info("API key almacenada para '%s' (expira: %s)", args.cliente,
                     api_key.fecha_expiracion.date())
        except Exception as e:
            print(f"La key se genero pero NO se pudo almacenar en la BD: {e}")
            sys.exit(1)
    else:
        print("(Modo solo-generar: la key NO se almaceno en la BD.)")
        print(f"Hash completo para insercion manual: {key_hash}")


if __name__ == "__main__":
    main()
