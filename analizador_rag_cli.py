#!/usr/bin/env python3
"""
Analizador de seguridad de código fuente con RAG (NVD + ChromaDB) usando Ollama.
Uso: python3 analizador_rag_cli.py <directorio_proyecto> [--update-nvd]
Genera informes en TXT y PDF con los hallazgos.
- Ctrl+C pregunta si cancelar; si sí, pregunta si generar informe parcial.
- Ignora carpetas de dependencias típicas.
- Los reportes tienen timestamp para historial.
- Analiza tanto archivos con extensiones reconocidas como archivos sin extensión (Dockerfile, .env, etc.).
"""

import os
import sys
import argparse
import datetime
import time
import signal
import requests
import chromadb
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

# ----------- CONFIGURACIÓN -----------
MODEL = "auditor-seguridad"              # Modelo experto en seguridad
EMBED_MODEL = "nomic-embed-text"         # Modelo para embeddings
COLLECTION_NAME = "nvd_vulnerabilities"
OLLAMA_URL = "http://localhost:11434/api"
CHROMA_HOST = "localhost"
CHROMA_PORT = "8001"
LAST_UPDATE_FILE = "last_nvd_update.txt"
CHUNK_SIZE = 12000                       # Caracteres máximos por archivo

# Directorios a ignorar durante el escaneo
IGNORE_DIRS = {
    'node_modules', 'vendor', 'venv', '__pycache__',
    '.git', '.svn', '.hg', 'dist', 'build', 'target',
    'bin', 'obj', 'packages', 'Pods', 'third_party',
    'external', '.idea', '.vscode', '.settings', '.metadata',
    'site-packages', 'bower_components', '.pytest_cache',
    '.mypy_cache', '.tox', 'egg-info', '.eggs',
    'cabal-sandbox', '.stack-work', 'result', 'coverage',
    'jspm_packages', '.angular', '.next', '.nuxt', '.output', '.cache'
}

# Archivos sin extensión que SIEMPRE se analizarán (nombres exactos)
WITHOUT_EXT_FILES = {
    'Dockerfile', 'Makefile', 'Vagrantfile', 'Gemfile', 'Rakefile',
    'Procfile', 'Jenkinsfile', '.env', 'hosts', 'known_hosts',
    'authorized_keys', 'config', 'sshd_config', 'nginx.conf',
    'docker-compose.yml', 'docker-compose.yaml'  # (por si acaso, aunque tienen extensión)
}

# Extensiones de archivo que se analizarán
CODE_EXTENSIONS = (
    ".py", ".js", ".ts", ".java", ".go", ".php", ".c", ".cpp",
    ".h", ".rb", ".html", ".txt", ".css", ".sql", ".sh", ".yml",
    ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".lock", ".gradle", ".pom", ".md",
    ".rst", ".tex", ".log", ".bash", ".zsh", ".fish",
    ".ps1", ".bat", ".cmd", ".vbs", ".wsf", ".pl", ".pm",
    ".r", ".rmd", ".swift", ".kt", ".scala", ".clj", ".lisp",
    ".lua", ".tcl", ".vim", ".el", ".ex", ".exs", ".erl", ".hrl",
    ".tf", ".hcl", ".bicep", ".proto", ".cap", ".gemspec",
    ".cabal", ".nix", ".ebuild", ".sbt", ".mk", ".cmake",
    ".gradle", ".m", ".mm", ".cs", ".vb", ".fs", ".fsx",
    ".tsx", ".jsx", ".vue", ".svelte", ".astro", ".prisma",
    ".graphql", ".gql", ".cyp", ".sol", ".rs", ".rlib",
    ".dart", ".jl", ".sc", ".scd", ".pde", ".ino",
    ".zig", ".odin", ".c3", ".hob", ".cobra", ".nim",
    ".wren", ".cr", ".elm", ".purs", ".dhall", ".cue",
    ".json5", ".jsonc", ".hjson", ".bson", ".yaml", ".toml",
    ".editorconfig", ".gitignore", ".gitattributes",
    ".dockerignore", ".npmignore", ".eslintignore",
    ".prettierignore", ".stylelintignore", ".babelrc",
    ".eslintrc", ".stylelintrc", ".postcssrc", ".browserslistrc"
)

# ------------------------------------

# Variables globales
report_lines = []
report_base_name = None

# -------------------------------------------------------------------
# FUNCIONES PARA LA BASE DE CONOCIMIENTO NVD
# -------------------------------------------------------------------

def fetch_cves_recent(days=90):
    """Obtiene todas las CVEs publicadas en los últimos 'days' días desde la API NVD 2.0."""
    end_date = datetime.datetime.now(datetime.timezone.utc)
    start_date = end_date - datetime.timedelta(days=days)

    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'pubStartDate': start_str,
        'pubEndDate': end_str,
        'resultsPerPage': 2000
    }

    all_cves = []
    while True:
        try:
            response = requests.get(base_url, params=params, timeout=30)
        except Exception as e:
            print(f"Error al conectar con la API NVD: {e}")
            break
        if response.status_code == 404:
            break
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])

        for vuln in vulnerabilities:
            cve = vuln['cve']
            desc = "Sin descripción"
            for d in cve.get('descriptions', []):
                if d['lang'] == 'en':
                    desc = d['value']
                    break
            metrics = cve.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
            severity = cvss_v3.get('baseSeverity', 'N/A')
            score = cvss_v3.get('baseScore', 'N/A')

            cve_info = {
                'id': cve['id'],
                'description': desc,
                'severity': severity,
                'score': score
            }
            all_cves.append(cve_info)

        total_results = data.get('totalResults', 0)
        if len(all_cves) >= total_results:
            break
        params['startIndex'] = data.get('startIndex', 0) + data.get('resultsPerPage', 0)
        time.sleep(0.6)

    return all_cves

def get_last_update_date():
    """Lee la fecha de la última actualización NVD desde el archivo local."""
    if not os.path.exists(LAST_UPDATE_FILE):
        return None
    with open(LAST_UPDATE_FILE) as f:
        return f.read().strip()

def set_last_update_date(date_str):
    """Guarda la fecha de la última actualización."""
    with open(LAST_UPDATE_FILE, "w") as f:
        f.write(date_str)

def connect_chroma():
    """Establece conexión con ChromaDB y devuelve la colección NVD (sin función de embedding)."""
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)
    return collection

def generate_embedding(text):
    """Genera el vector (embedding) para un único texto usando la API /api/embed de Ollama."""
    payload = {"model": EMBED_MODEL, "input": [text]}
    try:
        r = requests.post(f"{OLLAMA_URL}/embed", json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data["embeddings"][0]
    except Exception as e:
        print(f"Error generando embedding: {e}")
        return None

def update_nvd_collection(collection):
    """Actualiza la base NVD. Recomendamos usar update_nvd_db.py externamente."""
    print("(Para actualizar la base NVD ejecuta manualmente 'python3 update_nvd_db.py')")
    set_last_update_date(datetime.date.today().isoformat())

# -------------------------------------------------------------------
# ANÁLISIS CON RAG
# -------------------------------------------------------------------
def analyze_file_with_rag(collection, filepath, content):
    """
    Envía el contenido de un archivo al modelo 'auditor-seguridad',
    recuperando previamente CVEs relevantes de ChromaDB mediante embedding manual.
    """
    query = content[:500]
    query_embedding = generate_embedding(query)
    if query_embedding is None:
        retrieved = []
        print(f"  ⚠️ No se pudo generar embedding para la consulta de {filepath}.")
    else:
        results = collection.query(query_embeddings=[query_embedding], n_results=3)
        retrieved = results['documents'][0] if results['documents'] else []

    context_str = "Vulnerabilidades NVD relacionadas:\n" + "\n---\n".join(retrieved) if retrieved \
        else "No se encontraron CVEs relevantes en la base de conocimiento."

    prompt = f"""Utilizando el siguiente contexto de vulnerabilidades NVD:
{context_str}

Analiza el siguiente código del archivo {filepath} y reporta únicamente los hallazgos de seguridad importantes.
Sigue el formato: título, severidad, ubicación, descripción, recomendación de mitigación.

Código:
{content}"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 16384,
            "num_predict": 2048
        }
    }
    try:
        r = requests.post(f"{OLLAMA_URL}/generate", json=payload)
        if r.status_code == 200:
            return r.json().get("response", "")
        else:
            return f"Error al analizar: {r.text}"
    except Exception as e:
        return f"Excepción al conectar con Ollama: {e}"

# -------------------------------------------------------------------
# GENERACIÓN DE PDF
# -------------------------------------------------------------------
def generate_pdf(report_text, output_pdf):
    """Convierte el informe de texto a un PDF estructurado."""
    doc = SimpleDocTemplate(output_pdf, pagesize=A4,
                            rightMargin=15*mm, leftMargin=15*mm,
                            topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=6*mm)
    story.append(Paragraph("Informe de Seguridad del Proyecto", title_style))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"Generado el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 5*mm))

    parts = report_text.split("="*60)
    for part in parts:
        if not part.strip():
            continue
        lines = part.strip().splitlines()
        if not lines:
            continue
        header_line = lines[0].strip()
        story.append(Paragraph(f"<b>📄 {header_line}</b>", styles['Heading2']))
        story.append(Spacer(1, 2*mm))
        content = "\n".join(lines[1:]).strip()
        if content:
            code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, leading=10, wordWrap='CJK')
            story.append(Preformatted(content, code_style))
        story.append(Spacer(1, 4*mm))

    doc.build(story)
    print(f"📄 PDF generado: {output_pdf}")

# -------------------------------------------------------------------
# Manejador de Ctrl+C mejorado
# -------------------------------------------------------------------
def signal_handler(sig, frame):
    print("\n⚠️ Interrupción detectada (Ctrl+C).")

    if not report_lines:
        print("❌ No se ha analizado ningún archivo todavía. Saliendo sin generar informe.")
        sys.exit(0)

    while True:
        cancel = input("¿Desea cancelar el escaneo? (s/n): ").strip().lower()
        if cancel in ('s', 'si', 'sí'):
            while True:
                gen = input("¿Desea generar el informe parcial con lo analizado? (s/n): ").strip().lower()
                if gen in ('s', 'si', 'sí'):
                    print("📦 Generando informe parcial...")
                    report_text = "\n".join(report_lines)
                    with open(f"{report_base_name}.txt", "w", encoding="utf-8") as f:
                        f.write(report_text)
                    generate_pdf(report_text, f"{report_base_name}.pdf")
                    print(f"✅ Informe parcial guardado ({len(report_lines)} archivos analizados).")
                    print(f"   TXT: {report_base_name}.txt")
                    print(f"   PDF: {report_base_name}.pdf")
                    sys.exit(0)
                elif gen in ('n', 'no'):
                    print("Saliendo sin generar informe.")
                    sys.exit(0)
                else:
                    print("Por favor, responda 's' o 'n'.")
        elif cancel in ('n', 'no'):
            print("Continuando escaneo...")
            return  # Regresa al bucle principal y sigue analizando
        else:
            print("Por favor, responda 's' o 'n'.")

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    global report_lines, report_base_name

    # Registrar manejador de Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Analizador de seguridad de código con RAG y NVD")
    parser.add_argument("project_path", help="Ruta al directorio del proyecto a analizar")
    parser.add_argument("--update-nvd", action="store_true", help="Forzar actualización de la base NVD ahora")
    args = parser.parse_args()

    project_path = os.path.abspath(args.project_path)
    if not os.path.isdir(project_path):
        print(f"❌ Error: la ruta '{project_path}' no es un directorio válido.")
        sys.exit(1)

    # Generar nombre base con timestamp para los reportes
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    report_base_name = f"informe_seguridad_{timestamp}"

    # 1. Conectar a ChromaDB
    print("Conectando a ChromaDB...")
    collection = connect_chroma()

    # 2. Decidir si actualizar la NVD
    need_update = args.update_nvd
    if not need_update:
        last = get_last_update_date()
        if last is None:
            need_update = True
        else:
            try:
                last_date = datetime.date.fromisoformat(last)
                if (datetime.date.today() - last_date).days >= 7:
                    need_update = True
            except:
                need_update = True

    if need_update:
        update_nvd_collection(collection)

    # 3. Recorrer archivos del proyecto y analizarlos
    print(f"\n🔍 Iniciando análisis del proyecto: {project_path}")
    total_files = 0
    report_lines = []

    for root, dirs, files in os.walk(project_path, topdown=True):
        # Ignorar carpetas que están en la lista negra
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

        for file in files:
            # Analizar si tiene una extensión conocida o si es un archivo sin extensión de la lista
            if file.endswith(CODE_EXTENSIONS) or file in WITHOUT_EXT_FILES:
                total_files += 1
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    print(f"  ⚠️ No se pudo leer {path}: {e}")
                    continue

                if len(content) > CHUNK_SIZE:
                    content = content[:CHUNK_SIZE] + "\n... [TRUNCADO]"

                print(f"  Analizando {path}...")
                res = analyze_file_with_rag(collection, path, content)
                entry = f"{'='*60}\nARCHIVO: {path}\n{'='*60}\n{res}\n"
                report_lines.append(entry)

                # Guardar incrementalmente en TXT para no perder lo analizado
                with open(f"{report_base_name}.txt", "w", encoding="utf-8") as ftxt:
                    ftxt.write("\n".join(report_lines))

    if total_files == 0:
        print("❌ No se encontraron archivos de código fuente en el directorio (o todos estaban en directorios ignorados).")
        sys.exit(1)

    # Generar informe final
    report_text = "\n".join(report_lines)
    with open(f"{report_base_name}.txt", "w", encoding="utf-8") as ftxt:
        ftxt.write(report_text)
    generate_pdf(report_text, f"{report_base_name}.pdf")
    print(f"\n✅ Análisis completado. Archivos analizados: {total_files}.")
    print(f"   TXT: {report_base_name}.txt")
    print(f"   PDF: {report_base_name}.pdf")

if __name__ == "__main__":
    main()