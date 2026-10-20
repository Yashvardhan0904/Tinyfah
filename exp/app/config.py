import os
from pathlib import Path

from dotenv import load_dotenv

EXP_DIR = Path(__file__).resolve().parent.parent
load_dotenv(EXP_DIR / ".env")
load_dotenv()


def _as_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _as_csv(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


def _as_list(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0"))

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").strip().lower()
LLM_MODEL = os.getenv("LLM_MODEL", "").strip() or (OLLAMA_MODEL if LLM_PROVIDER == "ollama" else "")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "")
LLM_FALLBACKS = _as_list("LLM_FALLBACKS")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", str(OLLAMA_TEMPERATURE)))
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "1"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "0"))
LLM_STRUCTURED_METHOD = os.getenv("LLM_STRUCTURED_METHOD", "auto").strip().lower()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "")
XAI_API_KEY = os.getenv("XAI_API_KEY", "")
OPENAI_COMPATIBLE_API_KEY = os.getenv("OPENAI_COMPATIBLE_API_KEY", "")
OPENAI_COMPATIBLE_BASE_URL = os.getenv("OPENAI_COMPATIBLE_BASE_URL", "")

TINYFISH_URL = os.getenv("TINYFISH_URL", "https://api.browser.tinyfish.ai")
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "")

ALLOWED_HOSTS = _as_csv("EXPLOIT_ALLOWED_HOSTS")
OWNER_TOKEN = os.getenv("EXPLOIT_OWNER_TOKEN", "")
DRY_RUN = _as_bool("EXPLOIT_DRY_RUN", True)
ENABLE_STATE_CHANGE = _as_bool("EXPLOIT_ENABLE_STATE_CHANGE", False)
LOCAL_BROWSER_FALLBACK = _as_bool("EXPLOIT_LOCAL_BROWSER_FALLBACK", True)

MAX_REQUESTS_PER_RUN = int(os.getenv("MAX_REQUESTS_PER_RUN", "200"))
MAX_RPS = float(os.getenv("MAX_RPS", "2"))
MAX_CONCURRENT_SESSIONS = int(os.getenv("MAX_CONCURRENT_SESSIONS", "2"))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "65536"))

CANARY_PATH = os.getenv("CANARY_PATH", "/canary.txt")
CANARY_MARKER = os.getenv("CANARY_MARKER", "TINYFAH-CANARY")

TEST_USER_EMAIL = os.getenv("TEST_USER_EMAIL", "")
TEST_USER_PASSWORD = os.getenv("TEST_USER_PASSWORD", "")
TEST_ADMIN_EMAIL = os.getenv("TEST_ADMIN_EMAIL", "")
TEST_ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD", "")

DB_FILE = EXP_DIR / "exploit_runs.db"
DATABASE_URL = f"sqlite:///{DB_FILE}"
AUDIT_DIR = EXP_DIR / "audit"
SCREENSHOTS_DIR = EXP_DIR / "screenshots"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
