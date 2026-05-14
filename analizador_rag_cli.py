#!/usr/bin/env python3

import os
import sys
import argparse
import datetime
import time
import signal
import requests
import chromadb
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

# ================= CONFIGURACIÓN =================
MODEL = "auditor-seguridad"          # Modelo personalizado creado con Modelfile
EMBED_MODEL = "nomic-embed-text"     # Modelo de embeddings
COLLECTION_NAME = "nvd_vulnerabilities"
OLLAMA_URL = "http://localhost:11434/api"
CHROMA_HOST = "localhost"
CHROMA_PORT = "8001"
LAST_UPDATE_FILE = "last_nvd_update.txt"
CHUNK_SIZE = 8000                    # Caracteres máximos por archivo (reducido para RAM)
REPORT_DIR = "reportes"              # Carpeta donde se guardan los informes

# Temperatura para respuestas deterministas (0.0-2.0)
TEMPERATURE = 0.1

# Activar/desactivar el uso de RAG (contexto NVD)
RAG_ENABLED = True

# =================================================

# Directorios ignorados
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

# Archivos sin extensión que SIEMPRE se analizan
WITHOUT_EXT_FILES = {
    'Dockerfile', 'Makefile', 'Vagrantfile', 'Gemfile', 'Rakefile',
    'Procfile', 'Jenkinsfile', '.env', 'hosts', 'known_hosts',
    'authorized_keys', 'config', 'sshd_config', 'nginx.conf',
    'docker-compose.yml', 'docker-compose.yaml', 'Containerfile',
    'Dockerfile.prod', 'Dockerfile.dev', 'helmfile.yaml',
    'kustomization.yaml', 'deployment.yaml'
}

# Extensiones de archivo que se analizan
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
    ".json5", ".jsonc", ".hjson", ".bson",
    ".editorconfig", ".gitignore", ".gitattributes",
    ".dockerignore", ".npmignore", ".eslintignore",
    ".prettierignore", ".stylelintignore", ".babelrc",
    ".eslintrc", ".stylelintrc", ".postcssrc", ".browserslistrc",
    ".tfvars", ".tfplan", ".bicep", ".arm", ".auto.tfvars", ".hcl"
)

# Variables globales para Ctrl+C
report_lines = []
report_base_name = None

# -------------------------------------------------------------------
# FUNCIONES DE NVD Y CHROMADB
# -------------------------------------------------------------------

def fetch_cves_recent(days=90):
    """Obtiene CVEs de la API NVD 2.0 (últimos 'days' días)."""
    end_date = datetime.datetime.now(datetime.timezone.utc)
    start_date = end_date - datetime.timedelta(days=days)
    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'pubStartDate': start_str, 'pubEndDate': end_str, 'resultsPerPage': 2000}
    all_cves = []
    while True:
        try:
            resp = requests.get(base_url, params=params, timeout=30)
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            data = resp.json()
            for vuln in data.get('vulnerabilities', []):
                cve = vuln['cve']
                desc = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), "Sin descripción")
                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])
                cvss_data = metrics[0].get('cvssData', {}) if metrics else {}
                severity = cvss_data.get('baseSeverity', 'N/A')
                score = cvss_data.get('baseScore', 'N/A')
                all_cves.append({
                    'id': cve['id'],
                    'description': desc,
                    'severity': severity,
                    'score': score
                })
            total = data.get('totalResults', 0)
            if len(all_cves) >= total:
                break
            params['startIndex'] = data.get('startIndex', 0) + data.get('resultsPerPage', 0)
            time.sleep(0.6)
        except Exception as e:
            print(f"Error al conectar con la API NVD: {e}")
            break
    return all_cves

def get_last_update_date():
    if not os.path.exists(LAST_UPDATE_FILE):
        return None
    with open(LAST_UPDATE_FILE) as f:
        return f.read().strip()

def set_last_update_date(date_str):
    with open(LAST_UPDATE_FILE, "w") as f:
        f.write(date_str)

def connect_chroma():
    """Conecta a ChromaDB si RAG está activado; si no, devuelve None."""
    if not RAG_ENABLED:
        print("RAG desactivado, no se necesita ChromaDB.")
        return None
    try:
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        return client.get_or_create_collection(name=COLLECTION_NAME)
    except Exception as e:
        print(f"⚠️ No se pudo conectar a ChromaDB: {e}")
        print("   Asegúrate de que el contenedor chromadb esté corriendo.")
        sys.exit(1)

def generate_embedding(text):
    """Genera embedding para un texto único."""
    if not RAG_ENABLED:
        return None
    payload = {"model": EMBED_MODEL, "input": [text]}
    try:
        r = requests.post(f"{OLLAMA_URL}/embed", json=payload, timeout=60)
        r.raise_for_status()
        return r.json()["embeddings"][0]
    except Exception as e:
        print(f"Error generando embedding: {e}")
        return None

def update_nvd_collection(collection):
    print("(Para actualizar la base NVD ejecuta manualmente 'python3 update_nvd_db.py')")
    set_last_update_date(datetime.date.today().isoformat())

# -------------------------------------------------------------------
# ANÁLISIS CON RAG (PROMPT MEJORADO PARA BUSCAR TODO TIPO DE VULNERABILIDADES)
# -------------------------------------------------------------------

def analyze_file_with_rag(collection, filepath, content):
    # 1. Recuperar contexto NVD (si RAG está habilitado)
    if RAG_ENABLED and collection is not None:
        query = content[:500]
        query_embedding = generate_embedding(query)
        if query_embedding is None:
            retrieved = []
            print(f"  ⚠️ No se pudo generar embedding para {filepath}.")
        else:
            results = collection.query(query_embeddings=[query_embedding], n_results=3)
            retrieved = results['documents'][0] if results['documents'] else []
        context_str = "Vulnerabilidades NVD relacionadas:\n" + "\n---\n".join(retrieved) if retrieved \
            else "No se encontraron CVEs relevantes en la base de conocimiento."
    else:
        context_str = ""

    # 2. Construir el prompt para buscar cualquier vulnerabilidad
    prompt = f"""Eres un auditor de seguridad experto e implacable. Analiza el siguiente código fuente del archivo {filepath}.

Realiza un análisis completo en busca de **cualquier tipo de vulnerabilidad o mala práctica de seguridad**, incluyendo pero sin limitarte a: inyecciones, problemas de autenticación, exposición de datos, control de acceso, configuraciones incorrectas, XSS, subida de archivos, debilidades en IaC (Docker, Kubernetes, etc.), hardcodeo de credenciales, cabeceras HTTP mal configuradas, IDOR, LFI/RFI, y cualquier otra debilidad.

Para cada vulnerabilidad que encuentres, proporciona la información con este formato exacto:

Título:
• Severidad:
• Ubicación:
• Descripción:
• Mitigación:
• CVE o CWE:

Si no encuentras ninguna vulnerabilidad, responde únicamente: "No se encontraron vulnerabilidades".

{context_str}

Código a analizar:
{content}"""

    # 3. Enviar a Ollama
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 8192,           # Contexto reducido para RAM limitada
            "num_predict": 2048,
            "temperature": TEMPERATURE
        }
    }
    try:
        r = requests.post(f"{OLLAMA_URL}/generate", json=payload)
        if r.status_code == 200:
            return r.json().get("response", "")
        else:
            return f"Error al analizar: {r.text}"
    except Exception as e:
        return f"Excepción: {e}"

# -------------------------------------------------------------------
# GENERACIÓN DE PDF CORREGIDA
# -------------------------------------------------------------------

def generate_pdf(report_text, output_pdf):
    doc = SimpleDocTemplate(output_pdf, pagesize=A4,
                            rightMargin=15*mm, leftMargin=15*mm,
                            topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    story = []

    # Título principal
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=6*mm)
    story.append(Paragraph("Informe de Seguridad del Proyecto", title_style))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"Generado el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 5*mm))

    # Dividir por archivos
    parts = report_text.split("="*60)
    for part in parts:
        if not part.strip():
            continue
        lines = part.strip().splitlines()
        if not lines:
            continue

        # La primera línea es "ARCHIVO: ..."
        header_line = lines[0].strip()
        story.append(Paragraph(f"<b>📄 {header_line}</b>", styles['Heading2']))
        story.append(Spacer(1, 2*mm))

        # Procesar el resto del contenido línea por línea
        content_lines = lines[1:]
        i = 0
        while i < len(content_lines):
            line = content_lines[i].strip()
            if not line:
                i += 1
                continue

            # Si es el título de un hallazgo (comienza con "Título:")
            if line.startswith("Título:"):
                # Añadir en negrita
                story.append(Paragraph(f"<b>{line}</b>", styles['Normal']))
                i += 1
                # Acumular las líneas con "•" hasta el siguiente título o vacío
                bullet_lines = []
                while i < len(content_lines) and content_lines[i].strip().startswith("•"):
                    bullet_lines.append(content_lines[i].strip())
                    i += 1
                if bullet_lines:
                    bullets_text = "<br/>".join(bullet_lines)
                    # Estilo para los detalles
                    detail_style = ParagraphStyle('Detail', fontName='Helvetica', fontSize=9, leading=13, leftIndent=10*mm)
                    story.append(Paragraph(bullets_text, detail_style))
                # Pequeño espacio tras cada hallazgo
                story.append(Spacer(1, 2*mm))
            else:
                # Texto normal (descripciones, etc.)
                story.append(Paragraph(line, styles['Normal']))
                i += 1

        story.append(Spacer(1, 4*mm))

    doc.build(story)
    print(f"📄 PDF generado: {output_pdf}")
    
# MANEJADOR DE CTRL+C
# -------------------------------------------------------------------

def signal_handler(sig, frame):
    print("\n⚠️ Interrupción detectada (Ctrl+C).")

    if not report_lines:
        print("❌ No se ha analizado ningún archivo. Saliendo sin informe.")
        sys.exit(0)

    while True:
        cancel = input("¿Desea cancelar el escaneo? (s/n): ").strip().lower()
        if cancel in ('s', 'si', 'sí'):
            while True:
                gen = input("¿Desea generar el informe parcial? (s/n): ").strip().lower()
                if gen in ('s', 'si', 'sí'):
                    print("📦 Generando informe parcial...")
                    report_text = "\n".join(report_lines)
                    os.makedirs(REPORT_DIR, exist_ok=True)
                    txt_path = os.path.join(REPORT_DIR, f"{report_base_name}.txt")
                    pdf_path = os.path.join(REPORT_DIR, f"{report_base_name}.pdf")
                    with open(txt_path, "w", encoding="utf-8") as f:
                        f.write(report_text)
                    generate_pdf(report_text, pdf_path)
                    print(f"✅ Informe parcial guardado ({len(report_lines)} archivos).")
                    print(f"   TXT: {txt_path}")
                    print(f"   PDF: {pdf_path}")
                    sys.exit(0)
                elif gen in ('n', 'no'):
                    print("Saliendo sin informe.")
                    sys.exit(0)
                else:
                    print("Por favor, responda 's' o 'n'.")
        elif cancel in ('n', 'no'):
            print("Continuando escaneo...")
            return
        else:
            print("Por favor, responda 's' o 'n'.")

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------

def main():
    global report_lines, report_base_name

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Analizador de seguridad local con Ollama + ChromaDB")
    parser.add_argument("project_path", help="Ruta al directorio del proyecto")
    parser.add_argument("--update-nvd", action="store_true", help="Forzar actualización de la base NVD")
    args = parser.parse_args()

    project_path = os.path.abspath(args.project_path)
    if not os.path.isdir(project_path):
        print(f"❌ Error: la ruta '{project_path}' no es un directorio válido.")
        sys.exit(1)

    # Crear carpeta de reportes si no existe
    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    report_base_name = f"informe_seguridad_{timestamp}"
    txt_path = os.path.join(REPORT_DIR, f"{report_base_name}.txt")
    pdf_path = os.path.join(REPORT_DIR, f"{report_base_name}.pdf")

    print("Conectando a ChromaDB...")
    collection = connect_chroma()

    # Actualizar NVD si toca
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
    if need_update and RAG_ENABLED:
        update_nvd_collection(collection)
    elif need_update and not RAG_ENABLED:
        print("RAG desactivado, omitiendo actualización de NVD.")

    # Recorrer proyecto
    print(f"\n🔍 Iniciando análisis del proyecto: {project_path}")
    total_files = 0
    report_lines = []

    for root, dirs, files in os.walk(project_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

        for file in files:
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

                # Guardado incremental en la carpeta reportes/
                with open(txt_path, "w", encoding="utf-8") as ftxt:
                    ftxt.write("\n".join(report_lines))

    if total_files == 0:
        print("❌ No se encontraron archivos de código fuente en el directorio (o todos estaban ignorados).")
        sys.exit(1)

    # Generar informe final
    report_text = "\n".join(report_lines)
    with open(txt_path, "w", encoding="utf-8") as ftxt:
        ftxt.write(report_text)
    generate_pdf(report_text, pdf_path)
    print(f"\n✅ Análisis completado. Archivos analizados: {total_files}.")
    print(f"   TXT: {txt_path}")
    print(f"   PDF: {pdf_path}")

if __name__ == "__main__":
    main()
