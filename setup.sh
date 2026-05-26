#!/usr/bin/env bash
# ============================================================================
# setup.sh — Configuración automatizada del entorno de seguridad local
# ============================================================================
# Uso: chmod +x setup.sh && sudo ./setup.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log()  { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[✗]\033[0m %s\n" "$*"; exit 1; }

# ── 1. Verificar requisitos ────────────────────────────────────────────────

log "Verificando requisitos del sistema..."

command -v python3 >/dev/null 2>&1 || err "python3 no instalado."
command -v docker  >/dev/null 2>&1 || warn "Docker no instalado."
command -v nginx   >/dev/null 2>&1 || warn "Nginx no instalado."

PYTHON_VER=$(python3 --version | cut -d' ' -f2 | cut -d. -f1)
[ "$PYTHON_VER" -ge 3 ] || err "Se requiere Python 3+"

# ── 2. Entorno virtual ─────────────────────────────────────────────────────

log "Creando entorno virtual..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# ── 3. Dependencias ────────────────────────────────────────────────────────

log "Instalando dependencias Python..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

# ── 4. Archivo .env ────────────────────────────────────────────────────────

if [ ! -f ".env" ]; then
    log "Creando .env desde .env.example..."
    cp .env.example .env
    warn "⚠️  Edita .env con tus valores reales (contraseñas, hosts, etc.)"
else
    log ".env ya existe, no se sobrescribe."
fi

# ── 5. Base de datos PostgreSQL ────────────────────────────────────────────

log "Inicializando tablas en PostgreSQL..."
python3 database/init_db.py 2>/dev/null && log "Tablas creadas." \
    || warn "No se pudo inicializar la BD. ¿PostgreSQL está corriendo?"

# ── 6. Configuración de Nginx ──────────────────────────────────────────────

NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"

if [ -d "$NGINX_AVAILABLE" ]; then
    log "Instalando configuración de Nginx..."
    sudo cp nginx/openwebui.conf "$NGINX_AVAILABLE/openwebui"

    # Crear certificado SSL autofirmado para pruebas
    SSL_DIR="/etc/nginx/ssl"
    if [ ! -f "$SSL_DIR/seguridad.local.crt" ]; then
        log "Generando certificado SSL autofirmado..."
        sudo mkdir -p "$SSL_DIR"
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_DIR/seguridad.local.key" \
            -out "$SSL_DIR/seguridad.local.crt" \
            -subj "/CN=seguridad.local/O=SeguridadLocal/C=ES" \
            -addext "subjectAltName=DNS:seguridad.local,IP:127.0.0.1"
    fi

    # Habilitar sitio
    if [ ! -L "$NGINX_ENABLED/openwebui" ]; then
        sudo ln -sf "$NGINX_AVAILABLE/openwebui" "$NGINX_ENABLED/openwebui"
    fi

    # Verificar y recargar
    sudo nginx -t && sudo systemctl reload nginx \
        && log "Nginx configurado y recargado." \
        || warn "Error al recargar Nginx. Revisa la configuración manualmente."
else
    warn "No se encontró $NGINX_AVAILABLE. Saltando configuración de Nginx."
fi

# ── 7. Servicios Docker ────────────────────────────────────────────────────

if command -v docker &>/dev/null; then
    log "Levantando servicios Docker..."
    docker compose up -d 2>/dev/null && log "Servicios Docker levantados." \
        || warn "Error al levantar servicios Docker."
fi

# ── 8. Resumen final ───────────────────────────────────────────────────────

echo ""
log "═══════════════════════════════════════════════════════════════"
log "  Instalación completada"
log "═══════════════════════════════════════════════════════════════"
log ""
log "  Servicios:"
log "    Open WebUI:    https://seguridad.local (o http://localhost:3000)"
log "    Validation:    http://localhost:8000"
log "    API Docs:      http://localhost:8000/api/v1/docs"
log ""
log "  Próximos pasos:"
log "    1. Edita .env con tus valores"
log "    2. Genera una API key:  python3 generar_apikey.py --cliente \"Mi Cliente\""
log "    3. Añade conocimiento:  psql -d openwebui -c \"INSERT INTO ...\""
log "    4. Ejecuta análisis:    python3 analizador_rag_cli.py --api-key <KEY> /ruta/proyecto"
log ""
log "  Para producción:"
log "    - Configurar Let's Encrypt (certbot)"
log "    - Cambiar API_KEY_SALT en .env"
log "    - Revisar los rate limits en nginx/openwebui.conf"
log "═══════════════════════════════════════════════════════════════"
