#!/usr/bin/env python3
"""
Analizador de seguridad de código fuente con RAG (NVD + ChromaDB) usando Ollama.
Uso: python3 analizador_rag_cli.py <directorio_proyecto> [--update-nvd]
Genera informes en TXT y PDF con los hallazgos.
"""

import os
import sys
import argparse
import datetime
import time
import requests
import chromadb
from chromadb.utils import embedding_functions
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
# ------------------------------------

# -------------------------------------------------------------------
# FUNCIONES PARA LA BASE DE CONOCIMIENTO NVD
# -------------------------------------------------------------------

def fetch_cves_recent(days=90):
    """
    Obtiene todas las CVEs publicadas en los últimos 'days' días desde la API NVD 2.0.
    Retorna una lista de diccionarios con id, description, severity y score.
    """
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
        response = requests.get(base_url, params=params)
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
    """Establece conexión con ChromaDB y devuelve la colección NVD."""
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    ollama_ef = embedding_functions.OllamaEmbeddingFunction(
        url=f"{OLLAMA_URL}/embeddings",
        model_name=EMBED_MODEL,
    )
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ollama_ef
    )
    return collection

def update_nvd_collection(collection):
    """Descarga CVEs recientes y las guarda en ChromaDB."""
    print("🔄 Actualizando base de conocimiento NVD...")
    cves = fetch_cves_recent(days=90)
    if not cves:
        print("⚠️ No se obtuvieron CVEs. Continuando sin actualizar NVD.")
        return

    docs = []
    ids = []
    for cve in cves:
        doc = (f"CVE ID: {cve['id']}\n"
               f"Severidad: {cve['severity']} (CVSS: {cve['score']})\n"
               f"Descripción: {cve['description']}")
        docs.append(doc)
        ids.append(cve['id'])

    collection.upsert(documents=docs, ids=ids)
    set_last_update_date(datetime.date.today().isoformat())
    print(f"✅ Base NVD actualizada con {len(docs)} CVEs.")

# -------------------------------------------------------------------
# ANÁLISIS CON RAG
# -------------------------------------------------------------------

def analyze_file_with_rag(collection, filepath, content):
    """
    Envía el contenido de un archivo al modelo 'auditor-seguridad',
    recuperando previamente CVEs relevantes de ChromaDB.
    """
    # 1. Buscar vulnerabilidades similares en ChromaDB
    query = content[:500]   # usamos el inicio del archivo para la búsqueda
    results = collection.query(query_texts=[query], n_results=3)
    retrieved = results['documents'][0] if results['documents'] else []

    context_str = "Vulnerabilidades NVD relacionadas:\n" + "\n---\n".join(retrieved) if retrieved \
        else "No se encontraron CVEs relevantes en la base de conocimiento."

    # 2. Prompt enriquecido
    prompt = f"""Utilizando el siguiente contexto de vulnerabilidades NVD:
{context_str}

Analiza el siguiente código del archivo {filepath} y reporta únicamente los hallazgos de seguridad importantes.
Sigue el formato: título, severidad, ubicación, descripción, recomendación de mitigación.

Código:
{content}"""

    # 3. Enviar a Ollama
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 16384,    # ventana de contexto
            "num_predict": 2048  # tokens máximos de respuesta
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

    # Título
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=6*mm)
    story.append(Paragraph("Informe de Seguridad del Proyecto", title_style))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"Generado el {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 5*mm))

    # Dividir el texto por el separador de archivos
    parts = report_text.split("="*60)
    for part in parts:
        if not part.strip():
            continue
        lines = part.strip().splitlines()
        if not lines:
            continue
        # La primera línea suele ser "ARCHIVO: ruta"
        header_line = lines[0].strip()
        story.append(Paragraph(f"<b>📄 {header_line}</b>", styles['Heading2']))
        story.append(Spacer(1, 2*mm))
        # Resto del análisis
        content = "\n".join(lines[1:]).strip()
        if content:
            # Fuente pequeña monoespaciada para el análisis
            code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, leading=10, wordWrap='CJK')
            story.append(Preformatted(content, code_style))
        story.append(Spacer(1, 4*mm))

    doc.build(story)
    print(f"📄 PDF generado: {output_pdf}")

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analizador de seguridad de código con RAG y NVD")
    parser.add_argument("project_path", help="Ruta al directorio del proyecto a analizar")
    parser.add_argument("--update-nvd", action="store_true", help="Forzar actualización de la base NVD ahora")
    args = parser.parse_args()

    project_path = os.path.abspath(args.project_path)
    if not os.path.isdir(project_path):
        print(f"❌ Error: la ruta '{project_path}' no es un directorio válido.")
        sys.exit(1)

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
    report_lines = []
    total_files = 0

    for root, dirs, files in os.walk(project_path):
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".java", ".go", ".php", ".c", ".cpp", ".h", ".rb")):
                total_files += 1
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    print(f"  ⚠️ No se pudo leer {path}: {e}")
                    continue

                # Truncar archivos muy largos para no exceder el contexto
                if len(content) > CHUNK_SIZE:
                    content = content[:CHUNK_SIZE] + "\n... [TRUNCADO]"

                print(f"  Analizando {path}...")
                res = analyze_file_with_rag(collection, path, content)
                report_lines.append(f"{'='*60}\nARCHIVO: {path}\n{'='*60}\n{res}\n")

    if total_files == 0:
        print("❌ No se encontraron archivos de código fuente en el directorio.")
        sys.exit(1)

    # 4. Guardar informes TXT y PDF
    report_text = "\n".join(report_lines)
    with open("informe_seguridad.txt", "w", encoding="utf-8") as ftxt:
        ftxt.write(report_text)

    generate_pdf(report_text, "informe_seguridad.pdf")
    print(f"\n✅ Análisis completado. Archivos analizados: {total_files}.")
    print("   TXT: informe_seguridad.txt")
    print("   PDF: informe_seguridad.pdf")

if __name__ == "__main__":
    main()
