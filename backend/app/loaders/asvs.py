import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.config import DEFAULT_ASVS_FILENAME
from app.loaders.base import find_standard_file

_CACHED_ASVS_DATA: Optional[Dict[str, Any]] = None

def get_asvs_json_path() -> Path:
    return find_standard_file(DEFAULT_ASVS_FILENAME, "ASVS_JSON_PATH")

def load_asvs_data() -> Dict[str, Any]:
    global _CACHED_ASVS_DATA
    if _CACHED_ASVS_DATA is None:
        path = get_asvs_json_path()
        with open(path, "r", encoding="utf-8") as f:
            _CACHED_ASVS_DATA = json.load(f)
    return _CACHED_ASVS_DATA

def get_all_chapters() -> List[Dict[str, Any]]:
    data = load_asvs_data()
    return [
        {
            "shortcode": chap.get("Shortcode"),
            "ordinal": chap.get("Ordinal"),
            "name": chap.get("Name"),
            "short_name": chap.get("ShortName"),
            "section_count": len(chap.get("Items", [])),
        }
        for chap in data.get("Requirements", [])
    ]

def get_one_test_per_chapter() -> List[Dict[str, Any]]:
    """Returns exactly 1 test requirement from each chapter (V1 through V17)."""
    data = load_asvs_data()
    selected_tests = []

    for chap in data.get("Requirements", []):
        chap_code = chap.get("Shortcode")
        chap_name = chap.get("Name")
        sections = chap.get("Items", [])
        if not sections:
            continue

        for sec in sections:
            sec_name = sec.get("Name")
            reqs = sec.get("Items", [])
            if reqs:
                first_req = reqs[0]
                selected_tests.append({
                    "requirement_id": first_req.get("Shortcode"),
                    "chapter_code": chap_code,
                    "chapter_name": chap_name,
                    "section_name": sec_name,
                    "description": first_req.get("Description"),
                    "level": first_req.get("L", "1"),
                })
                break

    return selected_tests

def get_first_n_tests(n: int = 5) -> List[Dict[str, Any]]:
    """Returns the first n requirements from the ASVS specification."""
    data = load_asvs_data()
    selected = []
    for chap in data.get("Requirements", []):
        chap_code = chap.get("Shortcode")
        chap_name = chap.get("Name")
        for sec in chap.get("Items", []):
            sec_name = sec.get("Name")
            for req in sec.get("Items", []):
                selected.append({
                    "requirement_id": req.get("Shortcode"),
                    "chapter_code": chap_code,
                    "chapter_name": chap_name,
                    "section_name": sec_name,
                    "description": req.get("Description"),
                    "level": req.get("L", "1"),
                })
                if len(selected) >= n:
                    return selected
    return selected

def get_test_suite(suite_type: str = "chapter_sample") -> List[Dict[str, Any]]:
    """
    Selects tests based on suite_type:
    - 'first_five': first 5 tests in the specification
    - 'chapter_sample': 1 test per chapter across all 17 chapters
    - 'full': all requirements
    """
    if suite_type == "first_five":
        return get_first_n_tests(5)
    return get_one_test_per_chapter()
