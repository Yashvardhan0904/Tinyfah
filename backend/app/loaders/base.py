import os
from pathlib import Path
from typing import Optional
from app.config import BACKEND_DIR, ROOT_DIR

def find_standard_file(filename: str, env_var: Optional[str] = None) -> Path:
    """Finds a standards JSON file across environment variables and standard project search paths."""
    if env_var:
        env_val = os.getenv(env_var)
        if env_val and Path(env_val).is_file():
            return Path(env_val).resolve()

    candidates = [
        Path(filename),
        ROOT_DIR / filename,
        BACKEND_DIR / filename,
        Path("..") / filename,
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()

    raise FileNotFoundError(f"Required file '{filename}' not found.")
