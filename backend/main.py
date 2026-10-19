"""FastAPI entry point re-exporting the application and route controllers."""
from app.api.app import app, create_app, lifespan
from app.models.scan import Scan, ScanRequest
from app.api.routes.scans import normalize_scan_record as _normalize_scan_record

__all__ = [
    "app",
    "create_app",
    "lifespan",
    "Scan",
    "ScanRequest",
    "_normalize_scan_record",
]
