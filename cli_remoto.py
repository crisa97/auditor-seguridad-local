#!/usr/bin/env python3
"""
CLI remoto para analisis de seguridad.
Envia archivos a un servidor central que ejecuta el pipeline RAG + LLM.
El reporte PDF se almacena en el servidor y es accesible via URL.

Uso:
    python cli_remoto.py --server https://midominio.com --api-key sk_abc... /ruta/al/proyecto
"""
import argparse
import os
import sys

try:
    import requests
except ImportError:
    print("Error: se requiere la libreria 'requests'. Instalala con: pip install requests")
    sys.exit(1)

# Mismos filtros que el servidor (src/infrastructure/config.py)
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
    ".m", ".mm", ".cs", ".vb", ".fs", ".fsx",
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
    ".tfvars", ".tfplan", ".arm", ".auto.tfvars", ".hcl",
)

WITHOUT_EXT_FILES = {
    "Dockerfile", "Makefile", "Vagrantfile", "Gemfile", "Rakefile",
    "Procfile", "Jenkinsfile", ".env", "hosts", "known_hosts",
    "authorized_keys", "config", "sshd_config", "nginx.conf",
    "docker-compose.yml", "docker-compose.yaml", "Containerfile",
    "Dockerfile.prod", "Dockerfile.dev", "helmfile.yaml",
    "kustomization.yaml", "deployment.yaml",
}

IGNORE_DIRS = {
    "node_modules", "vendor", "venv", "__pycache__",
    ".git", ".svn", ".hg", "dist", "build", "target",
    "bin", "obj", "packages", "Pods", "third_party",
    "external", ".idea", ".vscode", ".settings", ".metadata",
    "site-packages", "bower_components", ".pytest_cache",
    ".mypy_cache", ".tox", "egg-info", ".eggs",
    "cabal-sandbox", ".stack-work", "result", "coverage",
    "jspm_packages", ".angular", ".next", ".nuxt", ".output", ".cache",
}

MAX_FILE_SIZE = 1024 * 512  # 512 KB max per file


def _debe_analizar(filename: str) -> bool:
    if filename in WITHOUT_EXT_FILES:
        return True
    _, ext = os.path.splitext(filename)
    return ext.lower() in CODE_EXTENSIONS


def _leer_archivos(project_path: str) -> list[dict]:
    archivos = []
    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        print(f"Error: '{project_path}' no es un directorio valido.")
        sys.exit(1)

    for root, dirs, files in os.walk(project_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
        for file in files:
            if not _debe_analizar(file):
                continue
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, project_path)
            try:
                size = os.path.getsize(filepath)
                if size > MAX_FILE_SIZE:
                    print(f"  Omitiendo {rel_path} ({size} bytes, maximo {MAX_FILE_SIZE})")
                    continue
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if content.strip():
                    archivos.append({"filepath": rel_path, "contenido": content})
            except Exception as e:
                print(f"  Error al leer {rel_path}: {e}")

    return archivos


def _mostrar_resultado(data: dict):
    print(f"\n{'=' * 60}")
    print(f"  ID de analisis: {data.get('analisis_id', 'N/A')}")
    print(f"  Estado: {data.get('status', 'N/A')}")
    print(f"  Archivos analizados: {data.get('total_archivos', 0)}")
    print(f"  Vulnerabilidades encontradas: {data.get('total_hallazgos', 0)}")
    print(f"{'=' * 60}")

    hallazgos = data.get("hallazgos", [])
    if hallazgos:
        print(f"\n{'SEVERIDAD':<15} {'ARCHIVO':<40} {'TITULO'}")
        print(f"{'-' * 90}")
        for h in hallazgos:
            sev = h.get("severidad", "N/A")
            archivo = h.get("filepath", "")[-38:]
            titulo = (h.get("titulo", "") or "")[:50]
            print(f"{sev:<15} {archivo:<40} {titulo}")

    pdf_url = data.get("pdf_url", "")
    if pdf_url:
        print(f"\nReporte PDF disponible en: {pdf_url}")


def main():
    parser = argparse.ArgumentParser(
        description="CLI remoto de analisis de seguridad. Envia codigo a un servidor central para analisis RAG + LLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Ejemplos:
  %(prog)s --server https://auditor.ejemplo.com --api-key sk_abc... /ruta/al/proyecto
        """,
    )
    parser.add_argument("--server", required=True, help="URL del servidor de analisis (ej: https://auditor.ejemplo.com)")
    parser.add_argument("--api-key", required=True, help="API key con permiso rag:analizar")
    parser.add_argument("project_path", help="Ruta al directorio del proyecto a analizar")

    args = parser.parse_args()

    server_url = args.server.rstrip("/")
    api_key = args.api_key
    project_path = os.path.abspath(args.project_path)

    print(f"Leyendo archivos de: {project_path}")
    archivos = _leer_archivos(project_path)

    if not archivos:
        print("No se encontraron archivos de codigo para analizar.")
        sys.exit(1)

    print(f"Enviando {len(archivos)} archivos al servidor {server_url}...")

    payload = {
        "api_key": api_key,
        "nombre_proyecto": os.path.basename(project_path) or project_path,
        "archivos": archivos,
    }

    try:
        resp = requests.post(
            f"{server_url}/api/v2/rag/analizar",
            json=payload,
            timeout=600,
        )
    except requests.ConnectionError:
        print(f"Error: no se pudo conectar con {server_url}")
        sys.exit(1)
    except requests.Timeout:
        print("Error: el servidor no respondio a tiempo (timeout 600s)")
        sys.exit(1)
    except Exception as e:
        print(f"Error de conexion: {e}")
        sys.exit(1)

    if resp.status_code == 401:
        print(f"Error: API key invalida ({resp.status_code})")
        sys.exit(1)
    elif resp.status_code == 403:
        print(f"Error: permiso insuficiente (se requiere rag:analizar) ({resp.status_code})")
        sys.exit(1)
    elif resp.status_code != 200:
        print(f"Error del servidor (HTTP {resp.status_code}): {resp.text[:500]}")
        sys.exit(1)

    data = resp.json()
    _mostrar_resultado(data)


if __name__ == "__main__":
    main()
