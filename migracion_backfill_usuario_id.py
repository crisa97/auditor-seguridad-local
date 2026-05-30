#!/usr/bin/env python3
"""
Backfill: agrega usuarioId SOLO a colecciones analisis y hallazgos en MongoDB
que no lo tengan. NO modifica owasp, exploits ni cves.
Tambien migra la columna usuario_id en PostgreSQL api_keys si no existe.

Uso:
    python migracion_backfill_usuario_id.py
"""
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("backfill")


def migrar_mongodb():
    try:
        from src.adapters.mongodb.connection import MongoConnection
        db = MongoConnection.get_db()

        # Analisis
        result = db["analisis"].update_many(
            {"usuarioId": {"$exists": False}},
            {"$set": {"usuarioId": 0}},
        )
        log.info("MongoDB analisis actualizados: %d", result.modified_count)

        # Hallazgos
        result = db["hallazgos"].update_many(
            {"usuarioId": {"$exists": False}},
            {"$set": {"usuarioId": 0}},
        )
        log.info("MongoDB hallazgos actualizados: %d", result.modified_count)

    except Exception as e:
        log.error("Error en migracion MongoDB: %s", e)
        return False
    return True


def migrar_postgresql():
    try:
        from src.adapters.postgresql.connection import PostgresConnection
        conn = PostgresConnection.get_conn()
        cur = conn.cursor()

        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'api_keys' AND column_name = 'usuario_id'
                ) THEN
                    ALTER TABLE api_keys ADD COLUMN usuario_id INTEGER REFERENCES users(id) DEFAULT 0;
                END IF;
            END $$;
        """)
        cur.execute("UPDATE api_keys SET usuario_id = 0 WHERE usuario_id IS NULL")
        conn.commit()
        log.info("PostgreSQL migrado correctamente")
        PostgresConnection.return_conn(conn)
    except Exception as e:
        log.error("Error en migracion PostgreSQL: %s", e)
        return False
    return True


if __name__ == "__main__":
    log.info("=== Migracion v2: usuario_id ===")
    ok = True
    if not migrar_postgresql():
        ok = False
    if not migrar_mongodb():
        ok = False
    if ok:
        log.info("Migracion completada exitosamente.")
    else:
        log.error("Migracion completada con errores.")
        sys.exit(1)
