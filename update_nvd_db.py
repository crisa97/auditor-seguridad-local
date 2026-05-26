#! /usr/bin/env python3
"""
Wrapper backward-compatible.
"""
from src.infrastructure.di import get_sincronizador_nvd
from src.adapters.mongodb.connection import MongoConnection

def main():
    print("Verificando conexion a MongoDB...")
    if not MongoConnection.ping():
        print("No se pudo conectar a MongoDB.")

    sinc = get_sincronizador_nvd()
    sinc.execute()

if __name__ == "__main__":
    main()
