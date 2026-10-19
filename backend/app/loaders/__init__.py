"""Specification and standards loaders."""
from app.loaders.asvs import (
    load_asvs_data,
    get_all_chapters,
    get_one_test_per_chapter,
    get_first_n_tests,
    get_test_suite,
)
from app.loaders.tinyfah import (
    load_tinyfah_data,
    get_input_legend,
    get_mode_legend,
    get_all_chapters_summary,
    get_chapter_requirements,
    get_requirement,
)

__all__ = [
    "load_asvs_data",
    "get_all_chapters",
    "get_one_test_per_chapter",
    "get_first_n_tests",
    "get_test_suite",
    "load_tinyfah_data",
    "get_input_legend",
    "get_mode_legend",
    "get_all_chapters_summary",
    "get_chapter_requirements",
    "get_requirement",
]
