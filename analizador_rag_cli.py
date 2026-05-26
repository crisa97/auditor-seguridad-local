#!/usr/bin/env python3

import os
import sys
import argparse
import datetime
import signal
import requests
import chromadb
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

import mongo_integration as mongo
from config import (
    ANALYZER_MODEL, EMBEDDING_MODEL, OLLAMA_API_URL,
    CHROMA_HOST, CHROMA_PORT, CHROMA_NVD_COLLECTION,
    CHROMA_EXPLOIT_COLLECTION, CHROMA_QUERY_RESULTS,
    NVD_LAST_UPDATE_FILE, NVD_UPDATE_INTERVAL_DAYS,
    ANALYSIS_CHUNK_SIZE, ANALYSIS_QUERY_LENGTH,
    REPORT_OUTPUT_DIR, LLM_TEMPERATURE, LLM_NUM_CTX,
    LLM_NUM_PREDICT, EMBED_SINGLE_TIMEOUT,
    generate_single_embedding, get_last_update_date,
    set_last_update_date, fetch_cves_recent,
)

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

WITHOUT_EXT_FILES = {
    'Dockerfile', 'Makefile', 'Vagrantfile', 'Gemfile', 'Rakefile',
    'Procfile', 'Jenkinsfile', '.env', 'hosts', 'known_hosts',
    'authorized_keys', 'config', 'sshd_config', 'nginx.conf',
    'docker-compose.yml', 'docker-compose.yaml', 'Containerfile',
    'Dockerfile.prod', 'Dockerfile.dev', 'helmfile.yaml',
    'kustomization.yaml', 'deployment.yaml'
}

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

report_lines = []
report_base_name = None


# -------------------------------------------------------------------
# NVD
# -------------------------------------------------------------------

def update_nvd_collection(collection):
    print("(Para actualizar la base NVD ejecuta manualmente 'python3 update_nvd_db.py')")
    set_last_update_date()


# -------------------------------------------------------------------
# ChromaDB
# -------------------------------------------------------------------

def connect_chroma():
    try:
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        return client.get_or_create_collection(name=CHROMA_NVD_COLLECTION)
    except Exception as e:
        print(f"⚠️ No se pudo conectar a ChromaDB: {e}")
        print("   Asegúrate de que el contenedor chromadb esté corriendo.")
        sys.exit(1)


# -------------------------------------------------------------------
# ANÁLISIS CON RAG + MONGODB
# -------------------------------------------------------------------

_FIELD_MAP = [
    (("Título:", "Titulo:"), "titulo"),
    (("• Severidad:", "* Severidad:"), "severidad"),
    (("• Ubicación:", "* Ubicación:"), "ubicacion"),
    (("• Descripción:", "* Descripción:"), "descripcion"),
    (("• Mitigación:", "* Mitigación:"), "mitigacion"),
    (("• CVE o CWE:", "* CVE o CWE:"), "cve_cwe"),
]


def analyze_file_with_rag(collection, filepath, content):
    analisis_id = getattr(analyze_file_with_rag, "current_analisis_id", None)

    if collection is not None:
        query = content[:ANALYSIS_QUERY_LENGTH]
        query_embedding = generate_single_embedding(query)
        if query_embedding is None:
            retrieved_nvd = []
            retrieved_exploit = []
            print(f"  ⚠️ No se pudo generar embedding para {filepath}.")
        else:
            results_nvd = collection.query(
                query_embeddings=[query_embedding], n_results=CHROMA_QUERY_RESULTS
            )
            retrieved_nvd = results_nvd['documents'][0] if results_nvd['documents'] else []

            try:
                exploit_collection = chromadb.HttpClient(
                    host=CHROMA_HOST, port=CHROMA_PORT
                ).get_collection(name=CHROMA_EXPLOIT_COLLECTION)
                results_exploit = exploit_collection.query(
                    query_embeddings=[query_embedding], n_results=CHROMA_QUERY_RESULTS
                )
                retrieved_exploit = results_exploit['documents'][0] if results_exploit['documents'] else []
            except Exception:
                retrieved_exploit = []

        try:
            if mongo.ping():
                for i, doc_text in enumerate(retrieved_nvd):
                    cve_id_line = [l for l in doc_text.split('\n') if l.startswith("CVE ID:")]
                    if cve_id_line:
                        cve_id = cve_id_line[0].replace("CVE ID:", "").strip()
                        cve_data = mongo.get_cve(cve_id)
                        if cve_data and cve_data.get('description'):
                            retrieved_nvd[i] = (
                                f"CVE ID: {cve_id}\n"
                                f"Severidad: {cve_data.get('severity', 'N/A')} "
                                f"(CVSS: {cve_data.get('score', 'N/A')})\n"
                                f"Descripción: {cve_data['description']}"
                            )

                for i, doc_text in enumerate(retrieved_exploit):
                    exp_data = mongo.get_db()["exploits"].find_one({"text": doc_text[:100]})
                    if exp_data:
                        retrieved_exploit[i] = exp_data.get("text", doc_text)
        except Exception:
            pass

        parts = []
        if retrieved_nvd:
            parts.append("**Vulnerabilidades NVD relacionadas:**\n" + "\n---\n".join(retrieved_nvd))
        if retrieved_exploit:
            parts.append("**Exploits públicos relacionados (ExploitDB):**\n" + "\n---\n".join(retrieved_exploit))
        context_str = "\n\n".join(parts) if parts else "No se encontraron CVEs ni exploits relevantes."
    else:
        context_str = ""

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

    payload = {
        "model": ANALYZER_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": LLM_NUM_CTX,
            "num_predict": LLM_NUM_PREDICT,
            "temperature": LLM_TEMPERATURE,
        }
    }
    try:
        r = requests.post(f"{OLLAMA_API_URL}/generate", json=payload)
        if r.status_code == 200:
            response = r.json().get("response", "")
            if analisis_id and mongo.ping():
                _parse_and_store_findings(analisis_id, filepath, response)
            return response
        else:
            return f"Error al analizar: {r.text}"
    except Exception as e:
        return f"Excepción: {e}"


def _parse_and_store_findings(analisis_id, filepath, response):
    if "No se encontraron vulnerabilidades" in response:
        return
    lines = response.strip().splitlines()
    current = {}
    for line in lines:
        line = line.strip()
        for prefixes, key in _FIELD_MAP:
            for prefix in prefixes:
                if line.startswith(prefix):
                    if key == "titulo" and current.get("titulo"):
                        _save_finding(analisis_id, filepath, current)
                        current = {}
                    current[key] = line.split(":", 1)[1].strip()
                    break
            else:
                continue
            break
    if current.get("titulo"):
        _save_finding(analisis_id, filepath, current)


def _save_finding(analisis_id, filepath, finding):
    try:
        mongo.guardar_hallazgo(
            analisis_id=analisis_id,
            filepath=filepath,
            severidad=finding.get("severidad", "Media"),
            titulo=finding.get("titulo", ""),
            descripcion=finding.get("descripcion", ""),
            mitigacion=finding.get("mitigacion", ""),
            ubicacion=finding.get("ubicacion", ""),
            cve_cwe=finding.get("cve_cwe", "N/A"),
        )
    except Exception:
        pass


# -------------------------------------------------------------------
# GENERACIÓN DE PDF
# -------------------------------------------------------------------

def _add_heading(story, text, style):
    story.append(Paragraph(text, style))
    story.append(Spacer(1, 2*mm))


def generate_pdf(report_text, output_pdf):
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

    _detail_style = ParagraphStyle('Detail', fontName='Helvetica', fontSize=9, leading=13, leftIndent=10*mm)

    parts = report_text.split("="*60)
    for part in parts:
        if not part.strip():
            continue
        split_lines = part.strip().splitlines()
        if not split_lines:
            continue

        _add_heading(story, f"<b>{split_lines[0].strip()}</b>", styles['Heading2'])

        content_lines = split_lines[1:]
        i = 0
        while i < len(content_lines):
            line = content_lines[i].strip()
            if not line:
                i += 1
                continue

            if line.startswith("Título:") or line.startswith("Titulo:"):
                story.append(Paragraph(f"<b>{line}</b>", styles['Normal']))
                i += 1
                bullet_lines = []
                while i < len(content_lines) and (content_lines[i].strip().startswith("•") or content_lines[i].strip().startswith("*")):
                    bullet_lines.append(content_lines[i].strip())
                    i += 1
                if bullet_lines:
                    story.append(Paragraph("<br/>".join(bullet_lines), _detail_style))
                story.append(Spacer(1, 2*mm))
            else:
                story.append(Paragraph(line, styles['Normal']))
                i += 1

        story.append(Spacer(1, 4*mm))

    doc.build(story)
    print(f"📄 PDF generado: {output_pdf}")


# -------------------------------------------------------------------
# MANEJADOR DE CTRL+C
# -------------------------------------------------------------------

def _confirmar(prompt_msg, opciones_afirmativas, opciones_negativas):
    while True:
        r = input(prompt_msg).strip().lower()
        if r in opciones_afirmativas:
            return True
        if r in opciones_negativas:
            return False
        print("Por favor, responda 's' o 'n'.")


def signal_handler(sig, frame):
    print("\n⚠️ Interrupción detectada (Ctrl+C).")

    if not report_lines:
        print("❌ No se ha analizado ningún archivo. Saliendo sin informe.")
        sys.exit(0)

    afirmativas = ('s', 'si', 'sí')
    negativas = ('n', 'no')

    if _confirmar("¿Desea cancelar el escaneo? (s/n): ", afirmativas, negativas):
        if _confirmar("¿Desea generar el informe parcial? (s/n): ", afirmativas, negativas):
            print("📦 Generando informe parcial...")
            report_text = "\n".join(report_lines)
            os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
            txt_path = os.path.join(REPORT_OUTPUT_DIR, f"{report_base_name}.txt")
            pdf_path = os.path.join(REPORT_OUTPUT_DIR, f"{report_base_name}.pdf")
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            generate_pdf(report_text, pdf_path)
            print(f"✅ Informe parcial guardado ({len(report_lines)} archivos).")
            print(f"   TXT: {txt_path}")
            print(f"   PDF: {pdf_path}")
            sys.exit(0)
        else:
            print("Saliendo sin informe.")
            sys.exit(0)
    else:
        print("Continuando escaneo...")


# -------------------------------------------------------------------
# FUNCIONALIDAD DE COLAS (QUEUE)
# -------------------------------------------------------------------

def submit_to_queue(project_path):
    try:
        from tasks import analizar_proyecto
        task = analizar_proyecto.delay(project_path)
        print(f"✅ Análisis encolado exitosamente.")
        print(f"   Task ID: {task.id}")
        print(f"   Puedes verificar el estado con: python3 {sys.argv[0]} --status {task.id}")
        return task.id
    except Exception as e:
        print(f"❌ Error al encolar el análisis: {e}")
        print("   Asegúrate de que Redis y el worker de Celery estén corriendo.")
        sys.exit(1)


def show_queue_status(task_id):
    try:
        from tasks import app as celery_app
        result = celery_app.AsyncResult(task_id)

        if result.state == "PENDING":
            print("⏳ Estado: PENDIENTE — esperando ser procesado.")
        elif result.state == "STARTED":
            print("🔄 Estado: EN PROCESO — el análisis se está ejecutando.")
        elif result.state == "SUCCESS":
            data = result.result
            print("✅ Estado: COMPLETADO.")
            if isinstance(data, dict):
                print(f"   ID de análisis: {data.get('analisis_id', 'N/A')}")
                print(f"   Archivos analizados: {data.get('total_files', 'N/A')}")
                print(f"   Reporte TXT: {data.get('reporte_txt', 'N/A')}")
                print(f"   Reporte PDF: {data.get('reporte_pdf', 'N/A')}")
        elif result.state == "FAILURE":
            print(f"❌ Estado: FALLIDO.")
            print(f"   Error: {result.info}")
        elif result.state == "RETRY":
            print("🔄 Estado: REINTENTANDO — se reintentará automáticamente.")
        else:
            print(f"📊 Estado: {result.state}")
    except Exception as e:
        print(f"❌ Error al consultar estado: {e}")
        print("   Asegúrate de que Redis esté corriendo.")


def list_queue_jobs():
    try:
        analisis_list = mongo.listar_analisis(limit=10)
        if not analisis_list:
            print("No hay análisis registrados.")
            return
        print(f"{'ID':<30} {'PROYECTO':<40} {'ESTADO':<15} {'FECHA':<25}")
        print("-" * 110)
        for a in analisis_list:
            aid = str(a["_id"])
            path = a.get("projectPath", "N/A")[-38:]
            estado = a.get("estado", "N/A")
            fecha = a.get("timestamp", datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{aid:<30} {path:<40} {estado:<15} {fecha:<25}")
    except Exception as e:
        print(f"❌ Error al listar análisis: {e}")


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------

def _should_update_nvd(args):
    if args.update_nvd:
        return True
    last = get_last_update_date()
    if last is None:
        return True
    try:
        last_date = datetime.date.fromisoformat(last)
        return (datetime.date.today() - last_date).days >= NVD_UPDATE_INTERVAL_DAYS
    except Exception:
        return True


def main():
    global report_lines, report_base_name

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description="Analizador de seguridad local con Ollama + ChromaDB + MongoDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s /ruta/al/proyecto              # Análisis directo
  %(prog)s --queue /ruta/al/proyecto      # Encolar análisis vía Celery
  %(prog)s --status <task_id>             # Ver estado de tarea encolada
  %(prog)s --list                          # Listar análisis realizados
  %(prog)s --update-nvd /ruta/al/proyecto # Forzar actualización NVD
        """
    )
    parser.add_argument("project_path", nargs="?", help="Ruta al directorio del proyecto")
    parser.add_argument("--queue", action="store_true",
                        help="Encolar el análisis en Celery en lugar de ejecutarlo directamente")
    parser.add_argument("--status", metavar="TASK_ID",
                        help="Consultar el estado de una tarea encolada")
    parser.add_argument("--list", action="store_true",
                        help="Listar todos los análisis registrados")
    parser.add_argument("--update-nvd", action="store_true",
                        help="Forzar actualización de la base NVD")

    args = parser.parse_args()

    if args.status:
        show_queue_status(args.status)
        return

    if args.list:
        list_queue_jobs()
        return

    if args.queue:
        if not args.project_path:
            print("❌ Debes especificar la ruta del proyecto para encolar.")
            sys.exit(1)
        project_path = os.path.abspath(args.project_path)
        if not os.path.isdir(project_path):
            print(f"❌ Error: la ruta '{project_path}' no es un directorio válido.")
            sys.exit(1)
        submit_to_queue(project_path)
        return

    if not args.project_path:
        parser.print_help()
        sys.exit(1)

    project_path = os.path.abspath(args.project_path)
    if not os.path.isdir(project_path):
        print(f"❌ Error: la ruta '{project_path}' no es un directorio válido.")
        sys.exit(1)

    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    report_base_name = f"informe_seguridad_{timestamp}"
    txt_path = os.path.join(REPORT_OUTPUT_DIR, f"{report_base_name}.txt")
    pdf_path = os.path.join(REPORT_OUTPUT_DIR, f"{report_base_name}.pdf")

    print("Conectando a ChromaDB...")
    collection = connect_chroma()

    need_update = _should_update_nvd(args)
    if need_update:
        update_nvd_collection(collection)

    analisis_id = None
    if mongo.ping():
        analisis_id = mongo.crear_analisis(project_path)
        mongo.actualizar_estado_analisis(analisis_id, mongo.ANALISIS_EN_PROCESO)
        analyze_file_with_rag.current_analisis_id = analisis_id
        print(f"📝 Análisis registrado en MongoDB (ID: {analisis_id})")
    else:
        print("⚠️ MongoDB no disponible. Los hallazgos no se persistirán.")

    print(f"\n🔍 Iniciando análisis del proyecto: {project_path}")
    total_files = 0
    report_lines.clear()

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

                if len(content) > ANALYSIS_CHUNK_SIZE:
                    content = content[:ANALYSIS_CHUNK_SIZE] + "\n... [TRUNCADO]"

                print(f"  Analizando {path}...")
                res = analyze_file_with_rag(collection, path, content)
                entry = f"{'='*60}\nARCHIVO: {path}\n{'='*60}\n{res}\n"
                report_lines.append(entry)

                with open(txt_path, "w", encoding="utf-8") as ftxt:
                    ftxt.write("\n".join(report_lines))

                if analisis_id:
                    mongo.actualizar_estado_analisis(
                        analisis_id, mongo.ANALISIS_EN_PROCESO,
                        archivosAnalizados=total_files
                    )

    if total_files == 0:
        print("❌ No se encontraron archivos de código fuente en el directorio.")
        if analisis_id:
            mongo.actualizar_estado_analisis(
                analisis_id, mongo.ANALISIS_FALLIDO,
                error="No se encontraron archivos de código"
            )
        sys.exit(1)

    report_text = "\n".join(report_lines)
    with open(txt_path, "w", encoding="utf-8") as ftxt:
        ftxt.write(report_text)
    generate_pdf(report_text, pdf_path)

    if analisis_id:
        mongo.actualizar_estado_analisis(
            analisis_id, mongo.ANALISIS_COMPLETADO,
            totalFiles=total_files, archivosAnalizados=total_files,
            reporteTxt=txt_path, reportePdf=pdf_path
        )

    print(f"\n✅ Análisis completado. Archivos analizados: {total_files}.")
    print(f"   TXT: {txt_path}")
    print(f"   PDF: {pdf_path}")
    if analisis_id:
        print(f"   MongoDB ID: {analisis_id}")


if __name__ == "__main__":
    main()
