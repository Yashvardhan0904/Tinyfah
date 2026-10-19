import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

DEFAULT_TINYFAH_FILENAME = "Tinyfah.json"
DEFAULT_ASVS_FILENAME = "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"

def _find_file(filename: str, env_var: Optional[str] = None) -> Path:
    if env_var:
        env_val = os.getenv(env_var)
        if env_val and Path(env_val).is_file():
            return Path(env_val).resolve()

    candidates = [
        Path(filename),
        Path("..") / filename,
        Path(__file__).resolve().parent / filename,
        Path(__file__).resolve().parent.parent / filename,
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()

    raise FileNotFoundError(f"Required file '{filename}' not found.")

_CACHED_TINYFAH: Optional[Dict[str, Any]] = None
_CACHED_ASVS_DESCRIPTIONS: Optional[Dict[str, str]] = None

def _load_asvs_descriptions() -> Dict[str, str]:
    global _CACHED_ASVS_DESCRIPTIONS
    if _CACHED_ASVS_DESCRIPTIONS is not None:
        return _CACHED_ASVS_DESCRIPTIONS

    desc_map: Dict[str, str] = {}
    try:
        asvs_path = _find_file(DEFAULT_ASVS_FILENAME, "ASVS_JSON_PATH")
        with open(asvs_path, "r", encoding="utf-8") as f:
            asvs_data = json.load(f)
            for chap in asvs_data.get("Requirements", []):
                for sec in chap.get("Items", []):
                    for req in sec.get("Items", []):
                        sc = req.get("Shortcode")
                        if sc:
                            desc_map[sc] = req.get("Description", "")
    except Exception:
        pass  # Fallback gracefully if standard JSON is not present

    _CACHED_ASVS_DESCRIPTIONS = desc_map
    return _CACHED_ASVS_DESCRIPTIONS

def load_tinyfah_data() -> Dict[str, Any]:
    global _CACHED_TINYFAH
    if _CACHED_TINYFAH is not None:
        return _CACHED_TINYFAH

    path = _find_file(DEFAULT_TINYFAH_FILENAME, "TINYFAH_JSON_PATH")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Enrich requirements with full ASVS descriptions
    desc_map = _load_asvs_descriptions()
    for req in data.get("requirements", []):
        sc = req.get("shortcode", "")
        if sc in desc_map:
            req["description"] = desc_map[sc]
        else:
            req["description"] = req.get("test_hint", "")

    _CACHED_TINYFAH = data
    return _CACHED_TINYFAH

def get_input_legend() -> Dict[str, str]:
    data = load_tinyfah_data()
    return data.get("input_legend", {})

def get_mode_legend() -> Dict[str, Any]:
    data = load_tinyfah_data()
    return data.get("mode_legend", {})

def get_all_chapters_summary() -> List[Dict[str, Any]]:
    data = load_tinyfah_data()
    chapters: Dict[str, Dict[str, Any]] = {}
    for req in data.get("requirements", []):
        ch_name = req.get("chapter", "Unknown")
        if ch_name not in chapters:
            chapters[ch_name] = {
                "chapter": ch_name,
                "count": 0,
                "browser_script_count": 0,
                "hybrid_count": 0,
                "review_count": 0,
            }
        chapters[ch_name]["count"] += 1
        mode = req.get("tinyfish_mode", "")
        if mode == "BROWSER_SCRIPT":
            chapters[ch_name]["browser_script_count"] += 1
        elif mode == "HYBRID":
            chapters[ch_name]["hybrid_count"] += 1
        elif mode == "REVIEW":
            chapters[ch_name]["review_count"] += 1

    return list(chapters.values())

def get_chapter_requirements(chapter: str = "V1") -> List[Dict[str, Any]]:
    """
    Returns all requirements for a chapter.
    Accepts prefix like 'V1' or full name like 'V1 Encoding and Sanitization'.
    """
    data = load_tinyfah_data()
    ch_norm = chapter.strip().lower()
    results = []

    for req in data.get("requirements", []):
        chap_field = req.get("chapter", "").lower()
        shortcode = req.get("shortcode", "").lower()

        # Check if chapter matches "v1" or "v1 encoding and sanitization" or starts with "v1."
        if (
            chap_field == ch_norm
            or chap_field.startswith(f"{ch_norm} ")
            or shortcode.startswith(f"{ch_norm}.")
            or (ch_norm == "v1" and chap_field.startswith("v1 "))
        ):
            results.append(req)

    return results

def get_requirement(shortcode: str) -> Optional[Dict[str, Any]]:
    data = load_tinyfah_data()
    sc_norm = shortcode.strip().upper()
    for req in data.get("requirements", []):
        if req.get("shortcode", "").upper() == sc_norm:
            return req
    return None
