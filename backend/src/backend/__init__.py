"""Entrypoint for package scripts."""
import uvicorn
from app.api.app import app

def main() -> None:
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

__all__ = ["main", "app"]
