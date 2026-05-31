-- ============================================================================
-- schema.sql — Migraciones para el módulo de validación y API keys
-- ============================================================================
-- Uso: psql -U openwebui -d openwebui -f schema.sql
-- ============================================================================

BEGIN;

-- 1. Conocimiento validado (anti-falsos positivos)
CREATE TABLE IF NOT EXISTS conocimiento_validado (
    id              SERIAL PRIMARY KEY,
    texto_afirmacion TEXT NOT NULL UNIQUE,
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

COMMENT ON TABLE conocimiento_validado IS
    'Afirmaciones validadas manualmente para filtrar falsos positivos del LLM.';

-- 2. Pendientes de validación
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

CREATE INDEX IF NOT EXISTS idx_pendiente_afirmacion
    ON pendiente_validacion (texto_afirmacion);

COMMENT ON TABLE pendiente_validacion IS
    'Afirmaciones no validadas que requieren revisión humana.';

-- 3. API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id              SERIAL PRIMARY KEY,
    key_hash        VARCHAR(255) NOT NULL UNIQUE,
    key_prefix      VARCHAR(8) NOT NULL,       -- primeros 8 chars para identificación
    nombre_cliente  VARCHAR(255) NOT NULL,
    fecha_creacion  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    fecha_expiracion TIMESTAMP WITH TIME ZONE,
    activa          BOOLEAN DEFAULT TRUE,
    permisos        VARCHAR(100) DEFAULT 'rag:leer',
    ultimo_uso      TIMESTAMP WITH TIME ZONE,
    usuario_id      INTEGER REFERENCES users(id) DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_apikey_hash
    ON api_keys USING hash (key_hash);

CREATE INDEX IF NOT EXISTS idx_apikey_activa
    ON api_keys (activa) WHERE activa = TRUE;

COMMENT ON TABLE api_keys IS
    'API keys para autenticación de clientes externos. Se almacena solo el hash.';

-- 4. Usuarios del dashboard web
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    nombre          VARCHAR(255) NOT NULL,
    rol             VARCHAR(20) NOT NULL DEFAULT 'usuario'
                    CHECK (rol IN ('admin', 'usuario')),
    activo          BOOLEAN DEFAULT TRUE,
    creado_en       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ultimo_login    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_users_email
    ON users (email);

CREATE INDEX IF NOT EXISTS idx_users_rol
    ON users (rol) WHERE activo = TRUE;

COMMENT ON TABLE users IS
    'Usuarios del dashboard web con roles admin/usuario.';

COMMIT;
