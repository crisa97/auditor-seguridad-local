import logging
import os
import datetime
from typing import Optional

from src.domain.models import Hallazgo
from src.domain.enums import EstadoAnalisis
from src.domain.exceptions import AnalisisError
from src.ports.repositories import IAnalisisRepository, IHallazgoRepository, ICveRepository
from src.ports.services import ILlmService, IEmbeddingService, IVectorStore, IReportGenerator
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


_FIELD_MAP = [
    (("Título:", "Titulo:"), "titulo"),
    (("• Severidad:", "* Severidad:", "- Severidad:"), "severidad"),
    (("• Ubicación:", "* Ubicación:", "- Ubicación:", "- Ubicacion:"), "ubicacion"),
    (("• Descripción:", "* Descripción:", "- Descripción:", "- Descripcion:"), "descripcion"),
    (("• Mitigación:", "* Mitigación:", "- Mitigación:", "- Mitigacion:"), "mitigacion"),
    (("• CVE o CWE:", "* CVE o CWE:", "- CVE o CWE:"), "cve_cwe"),
]


class AnalizarProyecto:
    def __init__(
        self,
        llm: ILlmService,
        embed: IEmbeddingService,
        vector_store: IVectorStore,
        hallazgo_repo: IHallazgoRepository,
        analisis_repo: IAnalisisRepository,
        cve_repo: Optional[ICveRepository] = None,
        report_gen: Optional[IReportGenerator] = None,
    ):
        self._llm = llm
        self._embed = embed
        self._vector_store = vector_store
        self._hallazgo_repo = hallazgo_repo
        self._analisis_repo = analisis_repo
        self._cve_repo = cve_repo
        self._report_gen = report_gen

    def execute(
        self,
        project_path: str,
        api_key: str = "",
        servicio_url: str = "",
    ) -> dict:
        project_path = os.path.abspath(project_path)
        if not os.path.isdir(project_path):
            raise AnalisisError(f"La ruta '{project_path}' no es un directorio valido")

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_base_name = f"informe_seguridad_{timestamp}"
        os.makedirs(settings.report_output_dir, exist_ok=True)
        txt_path = os.path.join(settings.report_output_dir, f"{report_base_name}.txt")
        pdf_path = os.path.join(settings.report_output_dir, f"{report_base_name}.pdf")

        analisis_id = self._analisis_repo.create(project_path)
        self._analisis_repo.update_state(analisis_id, EstadoAnalisis.EN_PROCESO)

        report_lines: list[str] = []
        total_files = 0

        for root, dirs, files in os.walk(project_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in settings.ignore_dirs and not d.startswith('.')]

            for file in files:
                if not (file.endswith(settings.code_extensions) or file in settings.without_ext_files):
                    continue
                total_files += 1
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    print(f"  No se pudo leer {path}: {e}")
                    continue

                if len(content) > settings.analysis_chunk_size:
                    content = content[:settings.analysis_chunk_size] + "\n... [TRUNCADO]"

                print(f"  Analizando {path}...")
                res = self._analizar_archivo(path, content, analisis_id)

                entry = f"{'=' * 60}\nARCHIVO: {path}\n{'=' * 60}\n{res}\n"
                report_lines.append(entry)

                self._analisis_repo.update_state(
                    analisis_id, EstadoAnalisis.EN_PROCESO,
                    archivosAnalizados=total_files,
                )

        if total_files == 0:
            self._analisis_repo.update_state(
                analisis_id, EstadoAnalisis.FALLIDO,
                error="No se encontraron archivos de codigo",
            )
            return {"analisis_id": analisis_id, "status": "error",
                    "message": "No se encontraron archivos de codigo"}

        report_text = "\n".join(report_lines)

        if self._report_gen:
            self._report_gen.generate_txt(report_text, txt_path)
            self._report_gen.generate_pdf(report_text, pdf_path)

        self._analisis_repo.update_state(
            analisis_id, EstadoAnalisis.COMPLETADO,
            totalFiles=total_files, archivosAnalizados=total_files,
            reporteTxt=txt_path, reportePdf=pdf_path,
        )

        if servicio_url and api_key:
            self._enviar_resultado(report_text, api_key, servicio_url, analisis_id)

        return {
            "analisis_id": analisis_id,
            "status": "completado",
            "total_files": total_files,
            "reporte_txt": txt_path,
            "reporte_pdf": pdf_path,
        }

    def _analizar_archivo(self, filepath: str, content: str, analisis_id: str) -> str:
        query = content[:settings.analysis_query_length]
        query_embedding = self._embed.generate(query)
        retrieved_nvd: list[str] = []
        retrieved_exploit: list[str] = []

        if query_embedding is not None:
            try:
                retrieved_nvd = self._vector_store.query(
                    query_embedding, settings.chroma_nvd_collection,
                    n_results=settings.chroma_query_results,
                )
            except Exception as e:
                logger.warning("Error querying ChromaDB NVD collection: %s", e)
            try:
                retrieved_exploit = self._vector_store.query(
                    query_embedding, settings.chroma_exploit_collection,
                    n_results=settings.chroma_query_results,
                )
            except Exception as e:
                logger.warning("Error querying ChromaDB ExploitDB collection: %s", e)
            if self._cve_repo:
                for i, doc_text in enumerate(retrieved_nvd):
                    for line in doc_text.split('\n'):
                        if line.startswith("CVE ID:"):
                            cve_id = line.replace("CVE ID:", "").strip()
                            cve = self._cve_repo.get_by_id(cve_id)
                            if cve and cve.description:
                                retrieved_nvd[i] = (
                                    f"CVE ID: {cve_id}\n"
                                    f"Severidad: {cve.severity} (CVSS: {cve.score})\n"
                                    f"Descripcion: {cve.description}"
                                )
                            break

        parts = []
        if retrieved_nvd:
            parts.append("**Vulnerabilidades NVD relacionadas:**\n" + "\n---\n".join(retrieved_nvd))
        if retrieved_exploit:
            parts.append("**Exploits publicos relacionados (ExploitDB):**\n" + "\n---\n".join(retrieved_exploit))
        context_str = "\n\n".join(parts) if parts else "No se encontraron CVEs ni exploits relevantes."

        prompt = f"""Eres un auditor de seguridad experto e implacable. Analiza el siguiente codigo fuente del archivo {filepath}.

Realiza un analisis completo en busca de **cualquier tipo de vulnerabilidad o mala practica de seguridad**, incluyendo pero sin limitarte a: inyecciones, problemas de autenticacion, exposicion de datos, control de acceso, configuraciones incorrectas, XSS, subida de archivos, debilidades en IaC (Docker, Kubernetes, etc.), hardcodeo de credenciales, cabeceras HTTP mal configuradas, IDOR, LFI/RFI, y cualquier otra debilidad.

Para cada vulnerabilidad que encuentres, proporciona la informacion con este formato exacto:

Título:
• Severidad:
• Ubicación:
• Descripción:
• Mitigación:
• CVE o CWE:

Si no encuentras ninguna vulnerabilidad, responde unicamente: "No se encontraron vulnerabilidades".

{context_str}

Codigo a analizar:
{content}"""

        response = self._llm.generate(prompt)
        self._parse_and_store_findings(analisis_id, filepath, response, raw_response=response)
        return response

    def _parse_and_store_findings(self, analisis_id: str, filepath: str, response: str, raw_response: str = "") -> None:
        if "No se encontraron vulnerabilidades" in response:
            return
        lines = response.strip().splitlines()
        current: dict[str, str] = {}
        for line in lines:
            line = line.strip()
            for prefixes, key in _FIELD_MAP:
                for prefix in prefixes:
                    if line.startswith(prefix):
                        if key == "titulo" and current.get("titulo"):
                            self._save_finding(analisis_id, filepath, current, raw_response=raw_response)
                            current = {}
                        current[key] = line.split(":", 1)[1].strip()
                        break
                else:
                    continue
                break
        if current.get("titulo"):
            self._save_finding(analisis_id, filepath, current, raw_response=raw_response)

    def _save_finding(self, analisis_id: str, filepath: str, finding: dict[str, str], raw_response: str = "") -> None:
        try:
            self._hallazgo_repo.store(Hallazgo(
                analisis_id=analisis_id,
                filepath=filepath,
                severidad=finding.get("severidad", "Media"),
                titulo=finding.get("titulo", ""),
                descripcion=finding.get("descripcion", ""),
                mitigacion=finding.get("mitigacion", ""),
                ubicacion=finding.get("ubicacion", ""),
                cve_cwe=finding.get("cve_cwe", "N/A"),
                raw_response=raw_response,
            ))
        except Exception as e:
            logger.warning("No se pudo guardar el hallazgo en MongoDB: %s", e)

    def _enviar_resultado(self, texto: str, api_key: str, servicio_url: str, analisis_id: str) -> None:
        import logging
        import requests
        log = logging.getLogger(__name__)
        try:
            payload = {
                "texto": texto[:5000],
                "api_key": api_key,
                "analisis_id": analisis_id,
            }
            r = requests.post(
                f"{servicio_url.rstrip('/')}/api/v1/rag/consultar",
                json=payload, timeout=30,
            )
            if r.status_code == 200:
                log.info("Resultado enviado al servicio de validacion.")
            else:
                log.warning("Error al enviar resultado: HTTP %s", r.status_code)
        except Exception as e:
            log.warning("No se pudo enviar resultado al servicio: %s", e)
