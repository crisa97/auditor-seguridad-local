-- ============================================================================
-- migracion_v2_usuario_id.sql
-- Agrega columna usuario_id a api_keys para asociar keys a usuarios del dashboard
-- ============================================================================

BEGIN;

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS usuario_id INTEGER REFERENCES users(id) DEFAULT 0;

-- Actualizar keys existentes con usuario_id = 0 (admin por defecto)
UPDATE api_keys SET usuario_id = 0 WHERE usuario_id IS NULL;

COMMIT;
