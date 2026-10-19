import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent

# Load environment variables
load_dotenv(BACKEND_DIR / ".env")
load_dotenv(ROOT_DIR / ".env")
load_dotenv()

# Service URLs & Keys
TINYFISH_URL = os.getenv("TINYFISH_URL", "https://api.browser.tinyfish.ai")
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
MAX_CONCURRENT_SESSIONS = int(os.getenv("MAX_CONCURRENT_SESSIONS", "2"))

# Database & Storage paths
DB_FILE = BACKEND_DIR / "scans.db"
DATABASE_URL = f"sqlite:///{DB_FILE}"
SCREENSHOTS_DIR = BACKEND_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

# Standard Data File Names
DEFAULT_ASVS_FILENAME = "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
DEFAULT_TINYFAH_FILENAME = "Tinyfah.json"
ASVS_JSON_PATH = os.getenv("ASVS_JSON_PATH")
TINYFAH_JSON_PATH = os.getenv("TINYFAH_JSON_PATH")
