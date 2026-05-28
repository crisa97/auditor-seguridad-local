from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Cve:
    id: str
    description: str
    severity: str = "N/A"
    score: str = "N/A"
    chroma_id: str = ""


@dataclass
class Exploit:
    id: str
    path: str
    text: str
    chroma_id: str = ""


@dataclass
class Hallazgo:
    analisis_id: str
    filepath: str
    severidad: str
    titulo: str
    descripcion: str
    mitigacion: str
    ubicacion: str
    cve_cwe: str
    raw_response: str = ""


@dataclass
class Analisis:
    id: str = ""
    project_path: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now())
    estado: str = "pendiente"
    total_files: int = 0
    archivos_analizados: int = 0
    task_id: str = ""
    reporte_txt: str = ""
    reporte_pdf: str = ""
    error: str = ""


@dataclass
class ApiKey:
    key_hash: str
    key_prefix: str
    nombre_cliente: str
    permisos: str = "rag:leer"
    activa: bool = True
    fecha_expiracion: Optional[datetime] = None
    ultimo_uso: Optional[datetime] = None


@dataclass
class OwaspTop10Entry:
    id: str
    category: str
    title: str
    content: str
    risk_rank: str = ""
    cwes: str = ""
    chroma_id: str = ""


@dataclass
class Afirmacion:
    texto: str
    es_verdadero: bool = False
    fuente: str = ""
