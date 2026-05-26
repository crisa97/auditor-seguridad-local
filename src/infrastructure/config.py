import os
import datetime
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    # Ollama
    analyzer_model: str = field(default_factory=lambda: os.getenv("ANALYZER_MODEL", "auditor-seguridad"))
    embedding_model: str = field(default_factory=lambda: os.getenv("EMBEDDING_MODEL", "nomic-embed-text"))
    ollama_api_url: str = field(default_factory=lambda: os.getenv("OLLAMA_API_URL", "http://localhost:11434/api"))
    ollama_base_url: str = field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
    llm_temperature: float = field(default_factory=lambda: float(os.getenv("LLM_TEMPERATURE", "0.1")))
    llm_num_ctx: int = field(default_factory=lambda: int(os.getenv("LLM_NUM_CTX", "8192")))
    llm_num_predict: int = field(default_factory=lambda: int(os.getenv("LLM_NUM_PREDICT", "2048")))
    ollama_timeout: int = field(default_factory=lambda: int(os.getenv("OLLAMA_TIMEOUT", "120")))

    # ChromaDB
    chroma_host: str = field(default_factory=lambda: os.getenv("CHROMA_HOST", "localhost"))
    chroma_port: str = field(default_factory=lambda: os.getenv("CHROMA_PORT", "8001"))
    chroma_nvd_collection: str = field(default_factory=lambda: os.getenv("CHROMA_NVD_COLLECTION", "nvd_vulnerabilities"))
    chroma_exploit_collection: str = field(default_factory=lambda: os.getenv("CHROMA_EXPLOIT_COLLECTION", "exploitdb_exploits"))
    chroma_page_size: int = field(default_factory=lambda: int(os.getenv("CHROMA_PAGE_SIZE", "1000")))
    chroma_query_results: int = field(default_factory=lambda: int(os.getenv("CHROMA_QUERY_RESULTS", "3")))

    # NVD API
    nvd_api_base_url: str = field(default_factory=lambda: os.getenv("NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"))
    nvd_days_back: int = field(default_factory=lambda: int(os.getenv("NVD_DAYS_BACK", "90")))
    nvd_page_size: int = field(default_factory=lambda: int(os.getenv("NVD_PAGE_SIZE", "2000")))
    nvd_api_timeout: int = field(default_factory=lambda: int(os.getenv("NVD_API_TIMEOUT", "30")))
    nvd_api_delay: float = field(default_factory=lambda: float(os.getenv("NVD_API_DELAY", "0.6")))
    nvd_last_update_file: str = field(default_factory=lambda: os.getenv("NVD_LAST_UPDATE_FILE", "last_nvd_update.txt"))
    nvd_update_interval_days: int = field(default_factory=lambda: int(os.getenv("NVD_UPDATE_INTERVAL_DAYS", "7")))

    # Embeddings
    embed_batch_timeout: int = field(default_factory=lambda: int(os.getenv("EMBED_BATCH_TIMEOUT", "300")))
    embed_max_retries: int = field(default_factory=lambda: int(os.getenv("EMBED_MAX_RETRIES", "2")))
    embed_single_timeout: int = field(default_factory=lambda: int(os.getenv("EMBED_SINGLE_TIMEOUT", "60")))

    # Analisis
    analysis_chunk_size: int = field(default_factory=lambda: int(os.getenv("ANALYSIS_CHUNK_SIZE", "8000")))
    analysis_query_length: int = field(default_factory=lambda: int(os.getenv("ANALYSIS_QUERY_LENGTH", "500")))
    report_output_dir: str = field(default_factory=lambda: os.getenv("REPORT_OUTPUT_DIR", "reportes"))

    # MongoDB
    mongo_uri: str = field(default_factory=lambda: os.getenv("MONGO_URI", "mongodb://admin:seguridad_local_pass@localhost:27017/vulnerabilidades?authSource=admin"))
    mongo_database: str = field(default_factory=lambda: os.getenv("MONGO_DATABASE_NAME", "vulnerabilidades"))
    mongo_timeout_ms: int = field(default_factory=lambda: int(os.getenv("MONGO_TIMEOUT_MS", "5000")))

    # ExploitDB
    exploitdb_repo_url: str = field(default_factory=lambda: os.getenv("EXPLOITDB_REPO_URL", "https://gitlab.com/exploit-database/exploitdb.git"))
    exploitdb_local_dir: str = field(default_factory=lambda: os.getenv("EXPLOITDB_LOCAL_DIR", "./exploitdb-local"))
    exploit_batch_size: int = field(default_factory=lambda: int(os.getenv("EXPLOIT_BATCH_SIZE", "10")))
    exploit_max_text_length: int = field(default_factory=lambda: int(os.getenv("EXPLOIT_MAX_TEXT_LENGTH", "2000")))

    # NVD batch
    nvd_batch_size: int = field(default_factory=lambda: int(os.getenv("NVD_BATCH_SIZE", "200")))

    # Celery
    celery_broker_url: str = field(default_factory=lambda: os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"))
    celery_result_backend: str = field(default_factory=lambda: os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"))

    # Validacion / API Keys
    db_url: str = field(default_factory=lambda: os.getenv("DB_URL", "postgresql://openwebui:openwebui_pass@localhost:5432/openwebui"))
    api_key_salt: str = field(default_factory=lambda: os.getenv("API_KEY_SALT", "cambiar_esto_salt_seguro_por_favor"))
    validation_service_url: str = field(default_factory=lambda: os.getenv("VALIDATION_SERVICE_URL", "http://localhost:8000"))

    # Codigo fuente
    code_extensions: tuple = field(default_factory=lambda: (
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
    ))
    ignore_dirs: set = field(default_factory=lambda: {
        'node_modules', 'vendor', 'venv', '__pycache__',
        '.git', '.svn', '.hg', 'dist', 'build', 'target',
        'bin', 'obj', 'packages', 'Pods', 'third_party',
        'external', '.idea', '.vscode', '.settings', '.metadata',
        'site-packages', 'bower_components', '.pytest_cache',
        '.mypy_cache', '.tox', 'egg-info', '.eggs',
        'cabal-sandbox', '.stack-work', 'result', 'coverage',
        'jspm_packages', '.angular', '.next', '.nuxt', '.output', '.cache',
    })
    without_ext_files: set = field(default_factory=lambda: {
        'Dockerfile', 'Makefile', 'Vagrantfile', 'Gemfile', 'Rakefile',
        'Procfile', 'Jenkinsfile', '.env', 'hosts', 'known_hosts',
        'authorized_keys', 'config', 'sshd_config', 'nginx.conf',
        'docker-compose.yml', 'docker-compose.yaml', 'Containerfile',
        'Dockerfile.prod', 'Dockerfile.dev', 'helmfile.yaml',
        'kustomization.yaml', 'deployment.yaml',
    })

    def get_nvd_date_range(self, days: int | None = None) -> tuple[str, str]:
        if days is None:
            days = self.nvd_days_back
        end = datetime.datetime.now(datetime.timezone.utc)
        start = end - datetime.timedelta(days=days)
        return start.strftime('%Y-%m-%dT%H:%M:%S.000'), end.strftime('%Y-%m-%dT%H:%M:%S.000')

    def get_last_update_date(self) -> str | None:
        filepath = self.nvd_last_update_file
        if not os.path.exists(filepath):
            return None
        with open(filepath) as f:
            return f.read().strip()

    def set_last_update_date(self, date_str: str | None = None) -> None:
        if date_str is None:
            date_str = datetime.date.today().isoformat()
        with open(self.nvd_last_update_file, "w") as f:
            f.write(date_str)


settings = Settings()
