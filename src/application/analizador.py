import hashlib
import logging
import os
import datetime
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Optional

from src.domain.models import Hallazgo
from src.domain.enums import EstadoAnalisis
from src.domain.exceptions import AnalisisError
from src.ports.repositories import IAnalisisRepository, IHallazgoRepository, ICveRepository
from src.ports.services import ILlmService, IEmbeddingService, IVectorStore, IReportGenerator
from src.infrastructure.config import settings

logger = logging.getLogger(__name__)


_FIELD_MAP = [
    (("\u2022 Severidad:", "* Severidad:", "- Severidad:", "**Severidad:"), "severidad"),
    (("\u2022 Ubicaci\u00f3n:", "\u2022 Ubicacion:", "* Ubicaci\u00f3n:", "* Ubicacion:", "- Ubicaci\u00f3n:", "- Ubicacion:", "**Ubicacion:"), "ubicacion"),
    (("\u2022 Descripci\u00f3n:", "\u2022 Descripcion:", "* Descripci\u00f3n:", "* Descripcion:", "- Descripci\u00f3n:", "- Descripcion:", "**Descripcion:"), "descripcion"),
    (("\u2022 Mitigaci\u00f3n:", "\u2022 Mitigacion:", "* Mitigaci\u00f3n:", "* Mitigacion:", "- Mitigaci\u00f3n:", "- Mitigacion:", "**Mitigacion:"), "mitigacion"),
    (("\u2022 CVE o CWE:", "* CVE o CWE:", "- CVE o CWE:", "**CVE o CWE:"), "cve_cwe"),
    (("\u2022 OWASP:", "* OWASP:", "- OWASP:", "OWASP:", "Owasp:", "**OWASP:"), "owasp"),
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
        self._ollama_sem = threading.Semaphore(settings.analysis_max_workers)
        self._embed_cache: dict[str, list[float]] = {}
        self._project_context: str = ""

    # ── Optimizacion: cache de CVEs ──────────────────────────────────────

    @lru_cache(maxsize=256)
    def _get_cve_enriched(self, cve_id: str) -> str:
        if not self._cve_repo:
            return cve_id
        try:
            cve = self._cve_repo.get_by_id(cve_id)
            if cve and cve.description:
                return (
                    f"CVE ID: {cve_id}\n"
                    f"Severidad: {cve.severity} (CVSS: {cve.score})\n"
                    f"Descripcion: {cve.description}"
                )
        except Exception as e:
            logger.debug("Error en cache CVE %s: %s", cve_id, e)
        return cve_id

    # ── Optimizacion: embedding unico por proyecto ───────────────────────

    def _build_project_context(self, all_files: list[dict]) -> str:
        file_list_text = "\n".join(
            f"- {af.get('filepath', '')} ({len(af.get('contenido', ''))} chars)"
            for af in all_files[:50]
        )
        query = f"Project files:\n{file_list_text}"
        hash_key = hashlib.md5(query.encode()).hexdigest()
        cached = self._embed_cache.get(hash_key)
        if cached is not None:
            query_embedding = cached
        else:
            query_embedding = self._embed.generate(query[:settings.analysis_query_length])
            if query_embedding:
                self._embed_cache[hash_key] = query_embedding

        retrieved_nvd: list[str] = []
        retrieved_exploit: list[str] = []
        if query_embedding is not None:
            try:
                retrieved_nvd = self._vector_store.query(
                    query_embedding, settings.chroma_nvd_collection,
                    n_results=settings.chroma_query_results,
                )
            except Exception as e:
                logger.warning("Error querying ChromaDB NVD: %s", e)
            try:
                retrieved_exploit = self._vector_store.query(
                    query_embedding, settings.chroma_exploit_collection,
                    n_results=settings.chroma_query_results,
                )
            except Exception as e:
                logger.warning("Error querying ChromaDB ExploitDB: %s", e)
            if self._cve_repo:
                for i, doc_text in enumerate(retrieved_nvd):
                    for line in doc_text.split('\n'):
                        if line.startswith("CVE ID:"):
                            cve_id = line.replace("CVE ID:", "").strip()
                            retrieved_nvd[i] = self._get_cve_enriched(cve_id)
                            break

        parts = []
        if retrieved_nvd:
            parts.append("**Vulnerabilidades NVD relacionadas:**\n" + "\n---\n".join(retrieved_nvd))
        if retrieved_exploit:
            parts.append("**Exploits publicos relacionados (ExploitDB):**\n" + "\n---\n".join(retrieved_exploit))
        context_str = "\n\n".join(parts) if parts else ""
        if len(context_str) > settings.analysis_max_context_chars:
            context_str = context_str[:settings.analysis_max_context_chars] + "\n... [CONTEXTO TRUNCADO]"
        self._project_context = context_str

    # ── Cargar archivos locales con filtros optimizados ──────────────────

    def _cargar_archivos(self, project_path: str) -> list[dict]:
        archivos = []
        max_bytes = settings.analysis_max_file_size_kb * 1024
        minified = settings.analysis_minified_extensions
        for root, dirs, files in os.walk(project_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in settings.ignore_dirs and not d.startswith('.')]
            for file in files:
                if not (file.endswith(settings.code_extensions) or file in settings.without_ext_files):
                    continue
                # saltar archivos minificados
                if file.endswith(minified):
                    continue
                path = os.path.join(root, file)
                try:
                    size = os.path.getsize(path)
                    if size > max_bytes:
                        logger.debug("Omitiendo %s (%d bytes)", path, size)
                        continue
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if content.strip():
                        rel = os.path.relpath(path, project_path)
                        archivos.append({"filepath": rel, "contenido": content})
                except Exception as e:
                    print(f"  No se pudo leer {path}: {e}")
        return archivos

    # ── Agrupar archivos pequenos en lotes ────────────────────────────────

    def _agrupar_archivos(self, archivos: list[dict]) -> list:
        """Divide archivos en items individuales (grandes) y lotes (chicos)."""
        items = []
        lote_actual = {"archivos": [], "codigo_total": "", "num_lineas": 0}
        small_limit = settings.analysis_small_file_lines
        combine = settings.analysis_combine_small_files

        for af in archivos:
            content = af["contenido"]
            num_lines = content.count("\n") + 1

            if not combine or num_lines > small_limit:
                if lote_actual["archivos"]:
                    items.append(dict(lote_actual))
                    lote_actual = {"archivos": [], "codigo_total": "", "num_lineas": 0}
                items.append({"archivos": [af], "codigo_total": content, "num_lineas": num_lines})
                continue

            # archivo pequeño → agregar al lote
            new_total = lote_actual["num_lineas"] + num_lines
            new_size = len(lote_actual["codigo_total"]) + len(content)
            if lote_actual["archivos"] and (new_total > small_limit * 5 or new_size > settings.analysis_chunk_size):
                items.append(dict(lote_actual))
                lote_actual = {"archivos": [], "codigo_total": "", "num_lineas": 0}

            label = af["filepath"]
            sep = f"\n\n# --- {label} ---\n"
            lote_actual["archivos"].append(af)
            lote_actual["codigo_total"] += sep + content
            lote_actual["num_lineas"] += num_lines

        if lote_actual["archivos"]:
            items.append(dict(lote_actual))

        return items

    # ── Analisis individual (hilo seguro) ────────────────────────────────

    def _analizar_item(
        self,
        item: dict,
        analisis_id: str,
        report_lines: list,
        report_lock: threading.Lock,
    ) -> int:
        """Analiza un item (archivo individual o lote de archivos chicos)."""
        codigo = item["codigo_total"]
        archivos = item["archivos"]
        label = archivos[0]["filepath"] if len(archivos) == 1 else f"lote de {len(archivos)} archivos"

        with self._ollama_sem:
            prompt = self._build_prompt(label, codigo, self._project_context)
            response = self._llm.generate(prompt)

        if not response:
            return 0

        has_valid = "No se encontraron vulnerabilidades" not in response
        file_vuln_count = 0

        if has_valid:
            for af in archivos:
                self._parse_and_store_findings(analisis_id, af["filepath"], response, raw_response=response)
                file_vuln_count += 1

        with report_lock:
            if file_vuln_count > 0:
                for af in archivos:
                    header = f"{'=' * 60}\nARCHIVO: {af['filepath']}\n{'=' * 60}"
                    report_lines.append(header + "\n" + response)
            else:
                for af in archivos:
                    report_lines.append(
                        f"{'=' * 60}\nARCHIVO: {af['filepath']}\n{'=' * 60}\nNo se encontraron vulnerabilidades.\n"
                    )

        return file_vuln_count

    # ── Execute principal ────────────────────────────────────────────────

    def execute(
        self,
        project_path: str,
        api_key: str = "",
        servicio_url: str = "",
        usuario_id: int = 0,
        archivos_remotos: list[dict] | None = None,
    ) -> dict:
        analisis_id = self._analisis_repo.create(project_path, usuario_id=usuario_id)
        self._analisis_repo.update_state(analisis_id, EstadoAnalisis.EN_PROCESO)

        # 1. Obtener lista de archivos
        if archivos_remotos is not None:
            archivos = [af for af in archivos_remotos if af.get("contenido", "").strip()]
        else:
            project_path = os.path.abspath(project_path)
            if not os.path.isdir(project_path):
                raise AnalisisError(f"La ruta '{project_path}' no es un directorio valido")
            archivos = self._cargar_archivos(project_path)

        total_files = len(archivos)
        if total_files == 0:
            self._analisis_repo.update_state(
                analisis_id, EstadoAnalisis.FALLIDO,
                error="No se encontraron archivos de codigo",
            )
            return {"analisis_id": analisis_id, "status": "error",
                    "message": "No se encontraron archivos de codigo"}

        # 2. Contexto unico de ChromaDB (una sola vez)
        self._build_project_context(archivos)

        # 3. Agrupar archivos pequenos en lotes
        items = self._agrupar_archivos(archivos)

        # 4. Procesar en paralelo
        report_lines: list[str] = []
        report_lock = threading.Lock()
        total_vulnerabilities = 0

        self._analisis_repo.update_state(
            analisis_id, EstadoAnalisis.EN_PROCESO,
            totalFiles=total_files,
        )

        max_workers = min(settings.analysis_max_workers, len(items))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for item in items:
                future = pool.submit(
                    self._analizar_item, item, analisis_id,
                    report_lines, report_lock,
                )
                futures[future] = item

            for future in as_completed(futures):
                try:
                    chunk = future.result()
                    total_vulnerabilities += chunk
                except Exception as e:
                    logger.error("Error en item de analisis: %s", e)

        # 5. Generar reportes
        pdf_bytes = None
        if total_vulnerabilities > 0 and report_lines:
            report_text = "\n".join(report_lines)
            if archivos_remotos is not None:
                if self._report_gen:
                    pdf_bytes = self._report_gen.generate_pdf_bytes(report_text)
                reporte_txt = report_text
                reporte_pdf = ""
            else:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                report_base_name = f"informe_seguridad_{timestamp}"
                os.makedirs(settings.report_output_dir, exist_ok=True)
                txt_path = os.path.join(settings.report_output_dir, f"{report_base_name}.txt")
                pdf_path = os.path.join(settings.report_output_dir, f"{report_base_name}.pdf")
                if self._report_gen:
                    self._report_gen.generate_txt(report_text, txt_path)
                    self._report_gen.generate_pdf(report_text, pdf_path)
                reporte_txt = txt_path
                reporte_pdf = pdf_path
                print(f"   TXT: {txt_path}")
                print(f"   PDF: {pdf_path}")
        else:
            reporte_txt = ""
            reporte_pdf = ""

        self._analisis_repo.update_state(
            analisis_id, EstadoAnalisis.COMPLETADO,
            totalFiles=total_files, archivosAnalizados=total_files,
            reporteTxt=reporte_txt, reportePdf=reporte_pdf,
        )

        if servicio_url and api_key:
            report_text = "\n".join(report_lines) if report_lines else "Sin hallazgos"
            self._enviar_resultado(report_text, api_key, servicio_url, analisis_id)

        result = {
            "analisis_id": analisis_id,
            "status": "completado",
            "total_files": total_files,
            "total_vulnerabilidades": total_vulnerabilities,
            "reporte_txt": reporte_txt,
            "reporte_pdf": reporte_pdf,
        }
        if pdf_bytes is not None:
            result["pdf_bytes"] = pdf_bytes
        return result

    def _build_prompt(self, filepath: str, full_code_block: str, context_str: str) -> str:
        ctx = f"\n\nContexto:\n{context_str}" if context_str else ""
        return (
            f"Analiza este codigo buscando vulnerabilidades de seguridad:\n"
            f"{ctx}\n\n{full_code_block}"
        )

    def _parse_and_store_findings(self, analisis_id: str, filepath: str, response: str, raw_response: str = "") -> None:
        if "No se encontraron vulnerabilidades" in response:
            return
        lines = response.strip().splitlines()
        current: dict[str, str] = {}
        saved_signatures: set[str] = set()
        prev_blank = True  # first content line acts as after-blank
        for line in lines:
            line = line.strip()
            if not line:
                prev_blank = True
                continue

            # Section headers like "Vulnerabilidad 1:" / "Hallazgo 1:" / "1. Injection SQL"
            if re.match(r"^(\d+[\.\)]\s|Vulnerabilidad\s+\d+|Hallazgo\s+\d+|Finding\s+\d+)", line, re.IGNORECASE):
                self._maybe_save_finding(analisis_id, filepath, current, saved_signatures, raw_response)
                current = {}
                # Strip the number prefix and use as title
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
                        # encountering a second "Severidad:" means a new finding
                        if key == "severidad" and current.get(key):
                            self._maybe_save_finding(analisis_id, filepath, current, saved_signatures, raw_response)
                            current = {}
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
                # After blank line → title of a new finding
                self._maybe_save_finding(analisis_id, filepath, current, saved_signatures, raw_response)
                current = {}
                current["titulo"] = line
            else:
                # Continuation text of previous field
                for prefixes, key in reversed(_FIELD_MAP):
                    if current.get(key):
                        current[key] += " " + line
                        break
            prev_blank = False

        self._maybe_save_finding(analisis_id, filepath, current, saved_signatures, raw_response)

    def _maybe_save_finding(self, analisis_id: str, filepath: str, current: dict[str, str],
                            saved_signatures: set[str], raw_response: str = "") -> None:
        if not any(current.values()):
            return
        # Skip entries without real fields (introductory text only)
        if not current.get("severidad") and not current.get("ubicacion"):
            return
        if not current.get("titulo"):
            current["titulo"] = current.get("severidad", "Hallazgo de seguridad")
        sig = (current.get("ubicacion", ""), current.get("descripcion", "")[:80])
        if sig not in saved_signatures:
            saved_signatures.add(sig)
            self._save_finding(analisis_id, filepath, current, raw_response=raw_response)

    def _save_finding(self, analisis_id: str, filepath: str, finding: dict[str, str], raw_response: str = "") -> None:
        try:
            analisis = self._analisis_repo.get_by_id(analisis_id)
            usuario_id = analisis.usuario_id if analisis else 0
            self._hallazgo_repo.store(Hallazgo(
                analisis_id=analisis_id,
                filepath=filepath,
                severidad=finding.get("severidad", "Media"),
                titulo=finding.get("titulo", ""),
                descripcion=finding.get("descripcion", ""),
                mitigacion=finding.get("mitigacion", ""),
                ubicacion=finding.get("ubicacion", ""),
                cve_cwe=finding.get("cve_cwe", "N/A"),
                owasp=finding.get("owasp", ""),
                raw_response=raw_response,
                usuario_id=usuario_id,
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
