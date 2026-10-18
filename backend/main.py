from dotenv import load_dotenv
# MUST run before importing scanner / agent_harness so GEMINI_API_KEY is in os.environ
load_dotenv()

from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from sqlmodel import Session, select
from database import init_db, get_session, Scan
from scanner import execute_scan_task

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Gemini + TinyFish Security Auditor", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: HttpUrl
    focus_prompt: Optional[str] = "Perform a full passive web vulnerability audit."

@app.post("/scans", response_model=Scan)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    # Initialize results with an empty agent_trace so the Next.js UI never hits null errors
    scan = Scan(
        url=str(payload.url),
        status="running",
        results={"agent_trace": [], "findings": []}
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        execute_scan_task,
        scan.id,
        scan.url,
        payload.focus_prompt
    )
    return scan

@app.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, db: Session = Depends(get_session)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scans", response_model=list[Scan])
def list_scans(db: Session = Depends(get_session)):
    return db.exec(select(Scan).order_by(Scan.created_at.desc()).limit(20)).all()
