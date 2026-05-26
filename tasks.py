import os
import datetime
from celery import Celery
from config import (
    CELERY_BROKER_URL, CELERY_RESULT_BACKEND,
    CHROMA_HOST, CHROMA_PORT, REPORT_OUTPUT_DIR,
)
import mongo_integration as mongo
from analizador_rag_cli import (
    connect_chroma, analyze_file_with_rag,
    IGNORE_DIRS, WITHOUT_EXT_FILES, CODE_EXTENSIONS,
    ANALYSIS_CHUNK_SIZE, generate_pdf,
)

app = Celery("seguridad_local", broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_max_tasks_per_child=1,
    task_reject_on_worker_lost=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

os.environ["CHROMA_HOST"] = CHROMA_HOST
os.environ["CHROMA_PORT"] = CHROMA_PORT


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def analizar_proyecto(self, project_path, task_id=None):
    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        raise FileNotFoundError(f"La ruta '{project_path}' no es un directorio válido.")

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    report_base_name = f"informe_seguridad_{timestamp}"
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    txt_path = os.path.join(REPORT_OUTPUT_DIR, f"{report_base_name}.txt")
    pdf_path = os.path.join(REPORT_OUTPUT_DIR, f"{report_base_name}.pdf")

    collection = connect_chroma()

    analisis_id = mongo.crear_analisis(project_path)
    mongo.actualizar_estado_analisis(
        analisis_id, mongo.ANALISIS_EN_PROCESO,
        taskId=task_id or self.request.id
    )

    report_lines = []
    total_files = 0

    try:
        for root, dirs, files in os.walk(project_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

            for file in files:
                if not (file.endswith(CODE_EXTENSIONS) or file in WITHOUT_EXT_FILES):
                    continue
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

                mongo.actualizar_estado_analisis(
                    analisis_id, mongo.ANALISIS_EN_PROCESO,
                    archivosAnalizados=total_files
                )

        if total_files == 0:
            mongo.actualizar_estado_analisis(
                analisis_id, mongo.ANALISIS_FALLIDO,
                error="No se encontraron archivos de código"
            )
            return {"analisis_id": analisis_id, "status": "error",
                    "message": "No se encontraron archivos de código"}

        report_text = "\n".join(report_lines)
        with open(txt_path, "w", encoding="utf-8") as ftxt:
            ftxt.write(report_text)
        generate_pdf(report_text, pdf_path)

        mongo.actualizar_estado_analisis(
            analisis_id, mongo.ANALISIS_COMPLETADO,
            totalFiles=total_files, archivosAnalizados=total_files,
            reporteTxt=txt_path, reportePdf=pdf_path
        )

        print(f"✅ Análisis completado. Archivos: {total_files}.")
        print(f"   TXT: {txt_path}")
        print(f"   PDF: {pdf_path}")

        return {
            "analisis_id": analisis_id,
            "status": "completado",
            "total_files": total_files,
            "reporte_txt": txt_path,
            "reporte_pdf": pdf_path,
        }

    except Exception as e:
        mongo.actualizar_estado_analisis(
            analisis_id, mongo.ANALISIS_FALLIDO,
            error=str(e), archivosAnalizados=total_files
        )
        raise self.retry(exc=e)
