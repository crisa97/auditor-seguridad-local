#!/usr/bin/env python3
"""
init_db.py — Inicializa las tablas en PostgreSQL.

Uso:
  python3 database/init_db.py                      # usa variables de entorno
  python3 database/init_db.py --db-url postgresql://...
"""
import argparse
import logging

from config import DB_URL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

SCHEMA_SQL = """
BEGIN;

CREATE TABLE IF NOT EXISTS conocimiento_validado (
    id              SERIAL PRIMARY KEY,
    texto_afirmacion TEXT NOT NULL,
    es_verdadero    BOOLEAN NOT NULL,
    fuente          VARCHAR(500),
    fecha_validacion TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    creado_en       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    actualizado_en  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_conocimiento_afirmacion
    ON conocimiento_validado USING hash (texto_afirmacion);

CREATE INDEX IF NOT EXISTS idx_conocimiento_verdadero
    ON conocimiento_validado (es_verdadero);

CREATE TABLE IF NOT EXISTS pendiente_validacion (
    id              SERIAL PRIMARY KEY,
    texto_afirmacion TEXT NOT NULL,
    consulta_original TEXT,
    modelo_respuesta TEXT,
    creado_en       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revisado        BOOLEAN DEFAULT FALSE,
    revisado_en     TIMESTAMP WITH TIME ZONE,
    revisado_por    VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_pendiente_revisado
    ON pendiente_validacion (revisado);

CREATE TABLE IF NOT EXISTS api_keys (
    id              SERIAL PRIMARY KEY,
    key_hash        VARCHAR(255) NOT NULL UNIQUE,
    key_prefix      VARCHAR(8) NOT NULL,
    nombre_cliente  VARCHAR(255) NOT NULL,
    fecha_creacion  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    fecha_expiracion TIMESTAMP WITH TIME ZONE,
    activa          BOOLEAN DEFAULT TRUE,
    permisos        VARCHAR(100) DEFAULT 'rag:leer',
    ultimo_uso      TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_apikey_hash
    ON api_keys USING hash (key_hash);

CREATE INDEX IF NOT EXISTS idx_apikey_activa
    ON api_keys (activa) WHERE activa = TRUE;

COMMIT;
"""


def init_db(db_url=None):
    if db_url is None:
        db_url = DB_URL
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(SCHEMA_SQL)
        cur.close()
        conn.close()
        log.info("✅ Tablas creadas/verificadas correctamente.")
        return True
    except Exception as e:
        log.error("❌ Error al inicializar la base de datos: %s", e)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inicializa tablas en PostgreSQL")
    parser.add_argument("--db-url", help="URL de conexión a PostgreSQL")
    args = parser.parse_args()
    success = init_db(args.db_url)
    exit(0 if success else 1)
