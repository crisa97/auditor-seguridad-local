#! /usr/bin/env python3
"""
Wrapper backward-compatible para indexar OWASP Top 10 2025.
"""
from src.infrastructure.di import get_indexador_owasp_top10
from src.adapters.mongodb.connection import MongoConnection


def main():
    print("Verificando conexion a MongoDB...")
    if not MongoConnection.ping():
        print("No se pudo conectar a MongoDB.")
        return

    idx = get_indexador_owasp_top10()
    idx.execute()


if __name__ == "__main__":
    main()