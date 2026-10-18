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

app = FastAPI(title="Hackathon Vulnerability Scanner", lifespan=lifespan)

# Allow Next.js local dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: HttpUrl

@app.post("/scans", response_model=Scan)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session),
):
    scan = Scan(url=str(payload.url), status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Runs asynchronously in the same process after returning HTTP 200
    background_tasks.add_task(execute_scan_task, scan.id, scan.url)
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
