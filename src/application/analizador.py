import logging
import os
import datetime
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from src.domain.models import Hallazgo
from src.domain.enums import EstadoAnalisis
from src.domain.exceptions import AnalisisError
from src.ports.repositories import IAnalisisRepository, IHallazgoRepository, ICveRepository
from src.ports.services import ILlmService, IEmbeddingService, IVectorStore, IReportGenerator
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)

_print_lock = threading.Lock()


def _safe_print(msg: str) -> None:
    with _print_lock:
        print(msg)


_FIELD_MAP = [
    (("•  Severidad:", "* Severidad:", "- Severidad:", "**Severidad:"), "severidad"),
    (("•  Ubicaci\u00f3n:", "•  Ubicacion:", "* Ubicaci\u00f3n:", "* Ubicacion:", "- Ubicaci\u00f3n:", "- Ubicacion:", "**Ubicacion:"), "ubicacion"),
    (("•  Descripci\u00f3n:", "•  Descripcion:", "* Descripci\u00f3n:", "* Descripcion:", "- Descripci\u00f3n:", "- Descripcion:", "**Descripcion:"), "descripcion"),
    (("•  Mitigaci\u00f3n:", "•  Mitigacion:", "* Mitigaci\u00f3n:", "* Mitigacion:", "- Mitigaci\u00f3n:", "- Mitigacion:", "**Mitigacion:"), "mitigacion"),
    (("•  CVE o CWE:", "* CVE o CWE:", "- CVE o CWE:", "**CVE o CWE:"), "cve_cwe"),
    (("•  OWASP:", "* OWASP:", "- OWASP:", "OWASP:", "Owasp:", "**OWASP:"), "owasp"),
]

# languages where indent signals block structure (Python, Ruby, etc.)
_INDENT_BASED = {"py", "rb", "rpy", "jl", "nim", "cobra", "wren"}
# function-start patterns per language group
_FUNC_RE = re.compile(
    r"^\s*"
    r"(?:"
    r"(?:async\s+)?def\s+\w+|"                         # Python def
    r"class\s+\w+|"                                     # Python/JS/Ruby class
    r"(?:export\s+)?(?:async\s+)?function\s+\w+|"       # JS/TS/PHP function
    r"(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*"     # JS arrow
    r"(?:async\s+)?(?:\([^)]*\)|\w+)\s*=>|"
    r"(?:public|private|protected|internal|static|"     # Java/C#/C++ access modifiers
    r"virtual|override|abstract|sealed|async)\s+"
    r"(?:\w+[<>\w]*\s+)?\w+\s*\(|"
    r"(?:public|private|protected|internal|static|"
    r"abstract|sealed)\s+class\s+\w+|"
    r"func\s+(?:\([^)]*\)\s+)?\w+\s*\(|"               # Go
    r"def\s+\w+|"                                       # Ruby
    r"fn\s+\w+|"                                        # Rust
    r"fun\s+\w+|"                                       # Kotlin
    r"(?:public|private|protected|static|abstract)"     # PHP method
    r"\s+function\s+\w+"
    r")",
    re.MULTILINE,
)


_ROUTE_RE = re.compile(
    r"^\s*(?:app|router|route|server)\s*\.\s*(?:get|post|put|delete|patch|use|all|head|options)\s*\("
)

_BLOCK_SPLIT_MIN = 5  # min lines per block when falling back to blank-line split


def _split_functions(code: str, ext: str) -> list[dict]:
    """Split code into logical chunks (functions, classes, route handlers, top-level blocks).

    Returns list of {name, start_line, end_line, code}.
    """
    lines = code.split("\n")
    n = len(lines)
    chunks: list[dict] = []
    chunk_start = 0
    chunk_name = "(top)"

    def flush(end: int):
        block = "\n".join(lines[chunk_start:end])
        if block.strip():
            chunks.append({
                "name": chunk_name,
                "start_line": chunk_start + 1,
                "end_line": end,
                "code": block,
            })

    is_indent = ext in _INDENT_BASED

    for i, line in enumerate(lines):
        m = _FUNC_RE.match(line)
        if m:
            flush(i)
            chunk_start = i
            raw = line.strip()
            for kw in ("class ", "function ", "def ", "func ", "fn ", "fun "):
                if kw in raw:
                    chunk_name = raw.split(kw, 1)[1].split("(")[0].split(":")[0].split("{")[0].strip()
                    break
            else:
                chunk_name = raw.split("(")[0].strip().split()[-1] if "(" in raw else raw[:50]
            continue

        rm = _ROUTE_RE.match(line)
        if rm:
            flush(i)
            chunk_start = i
            # extract route method + path
            route_match = line.strip()
            chunk_name = route_match.split("{")[0].strip()[:60]
            continue

        if not is_indent and not line.strip():
            if i + 1 < n:
                next_line = lines[i + 1]
                if _FUNC_RE.match(next_line) or _ROUTE_RE.match(next_line):
                    flush(i)
                    chunk_start = i + 1

    flush(n)

    # fallback: if no functions/routes found, split by blank lines into blocks
    if len(chunks) <= 1:
        chunks = []
        chunk_start = 0
        for i, line in enumerate(lines):
            if not line.strip() and i - chunk_start >= _BLOCK_SPLIT_MIN:
                block = "\n".join(lines[chunk_start:i])
                if block.strip():
                    chunks.append({
                        "name": f"(bloque l\u00ednea {chunk_start + 1})",
                        "start_line": chunk_start + 1,
                        "end_line": i,
                        "code": block,
                    })
                chunk_start = i + 1
        if chunk_start < n:
            block = "\n".join(lines[chunk_start:])
            if block.strip():
                chunks.append({
                    "name": f"(bloque l\u00ednea {chunk_start + 1})",
                    "start_line": chunk_start + 1,
                    "end_line": n,
                    "code": block,
                })

    if not chunks:
        chunks = [{"name": "(archivo completo)", "start_line": 1, "end_line": n, "code": code}]
    return chunks


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

        # Fase 1: recolectar archivos y leer contenido
        file_entries: list[tuple[str, str]] = []
        for root, dirs, files in os.walk(project_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in settings.ignore_dirs and not d.startswith('.')]
            for file in files:
                if not (file.endswith(settings.code_extensions) or file in settings.without_ext_files):
                    continue
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    _safe_print(f"  No se pudo leer {path}: {e}")
                    continue
                file_entries.append((path, content))

        total_files = len(file_entries)
        if total_files == 0:
            self._analisis_repo.update_state(
                analisis_id, EstadoAnalisis.FALLIDO,
                error="No se encontraron archivos de codigo",
            )
            return {"analisis_id": analisis_id, "status": "error",
                    "message": "No se encontraron archivos de codigo"}

        # Fase 2: generar embeddings en lote
        queries = [content[:settings.analysis_query_length] for _, content in file_entries]
        _safe_print(f"  Generando embeddings para {total_files} archivos...")
        all_embeddings = None
        try:
            batch_result = self._embed.generate_batch(queries)
            if batch_result:
                all_embeddings = batch_result
        except Exception as e:
            logger.warning("Error en batch embedding: %s", e)

        # Fase 3: analizar archivos en paralelo
        report_lines: list[str] = []
        total_vulnerabilities = 0
        all_findings_buffer: list[Hallazgo] = []

        _safe_print(f"  Analizando {total_files} archivos ({settings.analysis_concurrency} workers)...")
        with ThreadPoolExecutor(max_workers=settings.analysis_concurrency) as pool:
            futures = []
            for i, (path, content) in enumerate(file_entries):
                embedding = all_embeddings[i] if all_embeddings and i < len(all_embeddings) else None
                future = pool.submit(
                    self._analizar_archivo, path, content, analisis_id, embedding
                )
                futures.append(future)

            for future in as_completed(futures):
                try:
                    vuln_count, report_section, findings = future.result()
                    total_vulnerabilities += vuln_count
                    if report_section:
                        report_lines.append(report_section)
                    all_findings_buffer.extend(findings)
                except Exception as e:
                    logger.error("Error en thread de analisis: %s", e)

        # Fase 4: guardar hallazgos en lote
        if all_findings_buffer:
            try:
                self._hallazgo_repo.store_batch(all_findings_buffer)
            except Exception as e:
                logger.warning("No se pudieron guardar hallazgos en MongoDB: %s", e)

        # Fase 5: generar reportes
        reporte_txt = ""
        reporte_pdf = ""
        if total_vulnerabilities > 0 and report_lines:
            report_text = "\n".join(report_lines)
            if self._report_gen:
                self._report_gen.generate_txt(report_text, txt_path)
                self._report_gen.generate_pdf(report_text, pdf_path)
            reporte_txt = txt_path
            reporte_pdf = pdf_path
            _safe_print(f"   TXT: {txt_path}")
            _safe_print(f"   PDF: {pdf_path}")

        self._analisis_repo.update_state(
            analisis_id, EstadoAnalisis.COMPLETADO,
            totalFiles=total_files, archivosAnalizados=total_files,
            reporteTxt=reporte_txt, reportePdf=reporte_pdf,
        )

        if servicio_url and api_key:
            report_text = "\n".join(report_lines) if report_lines else "Sin hallazgos"
            self._enviar_resultado(report_text, api_key, servicio_url, analisis_id)

        return {
            "analisis_id": analisis_id,
            "status": "completado",
            "total_files": total_files,
            "total_vulnerabilidades": total_vulnerabilities,
            "reporte_txt": reporte_txt,
            "reporte_pdf": reporte_pdf,
        }

    def _analizar_archivo(
        self,
        filepath: str,
        content: str,
        analisis_id: str,
        query_embedding: Optional[list[float]],
    ) -> tuple[int, Optional[str], list[Hallazgo]]:
        _, ext = os.path.splitext(filepath)
        ext = ext.lstrip(".").lower()
        chunks = _split_functions(content, ext)

        _safe_print(f"  Analizando {filepath}...")
        retrieved_nvd: list[str] = []
        retrieved_exploit: list[str] = []

        if query_embedding is not None:
            # Consultas ChromaDB en paralelo
            with ThreadPoolExecutor(max_workers=2) as chroma_pool:
                f_nvd = chroma_pool.submit(
                    self._vector_store.query, query_embedding, settings.chroma_nvd_collection,
                    n_results=settings.chroma_query_results,
                )
                f_exploit = chroma_pool.submit(
                    self._vector_store.query, query_embedding, settings.chroma_exploit_collection,
                    n_results=settings.chroma_query_results,
                )
                try:
                    retrieved_nvd = f_nvd.result()
                except Exception as e:
                    logger.warning("Error querying ChromaDB NVD collection: %s", e)
                try:
                    retrieved_exploit = f_exploit.result()
                except Exception as e:
                    logger.warning("Error querying ChromaDB ExploitDB collection: %s", e)

            # Enriquecer CVEs (antes del prompt, igual que antes)
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
        context_str = "\n\n".join(parts) if parts else ""
        if len(context_str) > settings.analysis_max_context_chars:
            context_str = context_str[:settings.analysis_max_context_chars] + "\n... [CONTEXTO TRUNCADO]"

        # build a single prompt with ALL chunks from this file
        chunks_in_prompt = []
        total_code_len = 0
        for chunk in chunks:
            chunk_code = chunk["code"]
            remaining = settings.analysis_chunk_size - total_code_len
            if remaining <= 0:
                break
            if len(chunk_code) > remaining:
                chunk_code = chunk_code[:remaining] + "\n... [TRUNCADO]"
            total_code_len += len(chunk_code)
            label = f"{chunk['name']} (l\u00edneas {chunk['start_line']}-{chunk['end_line']})"
            chunks_in_prompt.append(f"=== {label} ===\n{chunk_code}")

        full_code_block = "\n\n".join(chunks_in_prompt)
        prompt = self._build_prompt(filepath, full_code_block, context_str)
        response = self._llm.generate(prompt)

        findings: list[Hallazgo] = []
        file_vuln_count = 0
        has_valid_response = bool(response and "No se encontraron vulnerabilidades" not in response)
        if has_valid_response:
            findings = self._parse_findings(analisis_id, filepath, response, raw_response=response)
            file_vuln_count = len(findings)

        report_section: Optional[str] = None
        if file_vuln_count > 0:
            header = f"{'=' * 60}\nARCHIVO: {filepath}\n{'=' * 60}"
            report_section = header + "\n" + response
        elif response:
            _safe_print(f"    {filepath} - No se encontraron vulnerabilidades.")
            report_section = (
                f"{'=' * 60}\nARCHIVO: {filepath}\n{'=' * 60}\nNo se encontraron vulnerabilidades.\n"
            )
        else:
            _safe_print(f"    {filepath} - Error: el modelo no respondi\u00f3 (timeout).")

        return file_vuln_count, report_section, findings

    def _build_prompt(self, filepath: str, full_code_block: str, context_str: str) -> str:
        ctx = f"\n\nContexto:\n{context_str}" if context_str else ""
        return (
            f"Analiza este codigo buscando vulnerabilidades de seguridad:\n"
            f"{ctx}\n\n{full_code_block}"
        )

    def _parse_findings(self, analisis_id: str, filepath: str, response: str, raw_response: str = "") -> list[Hallazgo]:
        if "No se encontraron vulnerabilidades" in response:
            return []
        lines = response.strip().splitlines()
        current: dict[str, str] = {}
        saved_signatures: set[str] = set()
        findings: list[Hallazgo] = []
        prev_blank = True

        def flush_finding():
            nonlocal current
            if not any(current.values()):
                return
            if not current.get("severidad") and not current.get("ubicacion"):
                return
            if not current.get("titulo"):
                current["titulo"] = current.get("severidad", "Hallazgo de seguridad")
            sig = (current.get("ubicacion", ""), current.get("descripcion", "")[:80])
            if sig not in saved_signatures:
                saved_signatures.add(sig)
                try:
                    findings.append(Hallazgo(
                        analisis_id=analisis_id,
                        filepath=filepath,
                        severidad=current.get("severidad", "Media"),
                        titulo=current.get("titulo", ""),
                        descripcion=current.get("descripcion", ""),
                        mitigacion=current.get("mitigacion", ""),
                        ubicacion=current.get("ubicacion", ""),
                        cve_cwe=current.get("cve_cwe", "N/A"),
                        owasp=current.get("owasp", ""),
                        raw_response=raw_response,
                    ))
                except Exception as e:
                    logger.warning("Error creando Hallazgo: %s", e)
            current = {}

        for line in lines:
            line = line.strip()
            if not line:
                prev_blank = True
                continue

            # Section headers like "Vulnerabilidad 1:" / "Hallazgo 1:" / "1. Injection SQL"
            if re.match(r"^(\d+[\.\)]\s|Vulnerabilidad\s+\d+|Hallazgo\s+\d+|Finding\s+\d+)", line, re.IGNORECASE):
                flush_finding()
                line = re.sub(r"^\d+[\.\)]\s*", "", line).strip()
                if line:
                    current["titulo"] = line
                prev_blank = True
                continue

            # Try to match known field prefixes (bullet fields)
            matched_prefix = False
            for prefixes, key in _FIELD_MAP:
                for prefix in prefixes:
                    if line.startswith(prefix):
                        if key == "severidad" and current.get(key):
                            flush_finding()
                        current[key] = line.split(":", 1)[1].strip()
                        matched_prefix = True
                        prev_blank = False
                        break
                if matched_prefix:
                    break

            if matched_prefix:
                continue

            # Line without any field prefix
            if prev_blank:
                flush_finding()
                current["titulo"] = line
            else:
                for prefixes, key in reversed(_FIELD_MAP):
                    if current.get(key):
                        current[key] += " " + line
                        break
            prev_blank = False

        flush_finding()
        return findings

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
