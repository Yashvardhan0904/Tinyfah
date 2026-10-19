from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import SCREENSHOTS_DIR, ROOT_DIR
from app.core.database import init_db
from app.api.routes.asvs import router as asvs_router
from app.api.routes.harness import router as harness_router
from app.api.routes.scans import router as scans_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

def create_app() -> FastAPI:
    app = FastAPI(
        title="OWASP ASVS Web Security Verification Harness",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.mount("/screenshots", StaticFiles(directory=str(SCREENSHOTS_DIR)), name="screenshots")

    app.include_router(asvs_router)
    app.include_router(harness_router)
    app.include_router(scans_router)
    app.include_router(scans_router, prefix="/api")

    frontend_dir = ROOT_DIR / "frontend"
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return app

app = create_app()
