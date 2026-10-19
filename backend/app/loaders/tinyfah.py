import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.config import DEFAULT_TINYFAH_FILENAME
from app.loaders.base import find_standard_file
from app.loaders.asvs import load_asvs_data

_CACHED_TINYFAH: Optional[Dict[str, Any]] = None
_CACHED_ASVS_DESCRIPTIONS: Optional[Dict[str, str]] = None

def _load_asvs_descriptions() -> Dict[str, str]:
    global _CACHED_ASVS_DESCRIPTIONS
    if _CACHED_ASVS_DESCRIPTIONS is not None:
        return _CACHED_ASVS_DESCRIPTIONS

    desc_map: Dict[str, str] = {}
    try:
        asvs_data = load_asvs_data()
        for chap in asvs_data.get("Requirements", []):
            for sec in chap.get("Items", []):
                for req in sec.get("Items", []):
                    sc = req.get("Shortcode")
                    if sc:
                        desc_map[sc] = req.get("Description", "")
    except Exception:
        pass

    _CACHED_ASVS_DESCRIPTIONS = desc_map
    return _CACHED_ASVS_DESCRIPTIONS

def load_tinyfah_data() -> Dict[str, Any]:
    global _CACHED_TINYFAH
    if _CACHED_TINYFAH is not None:
        return _CACHED_TINYFAH

    path = find_standard_file(DEFAULT_TINYFAH_FILENAME, "TINYFAH_JSON_PATH")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Enrich requirements with full ASVS descriptions
    desc_map = _load_asvs_descriptions()
    for req in data.get("requirements", []):
        sc = req.get("shortcode", "")
        req["description"] = desc_map.get(sc, req.get("test_hint", ""))

    _CACHED_TINYFAH = data
    return _CACHED_TINYFAH

def get_input_legend() -> Dict[str, str]:
    return load_tinyfah_data().get("input_legend", {})

def get_mode_legend() -> Dict[str, Any]:
    return load_tinyfah_data().get("mode_legend", {})

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
