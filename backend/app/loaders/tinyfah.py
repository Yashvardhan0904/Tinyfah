"""Backward-compatibility shim for TracePoint loader."""
from app.loaders.tracepoint import (
    load_tracepoint_data,
    load_tinyfah_data,
    get_input_legend,
    get_mode_legend,
    get_all_chapters_summary,
    get_chapter_requirements,
    get_requirement,
)

__all__ = [
    "load_tracepoint_data",
    "load_tinyfah_data",
    "get_input_legend",
    "get_mode_legend",
    "get_all_chapters_summary",
    "get_chapter_requirements",
    "get_requirement",
]
