"""
FastAPI Application Entry Point for AI-Powered Cyber Threat Intelligence System.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from contextlib import asynccontextmanager

from app.config import settings
from app.api.endpoints import router as api_router
from app.simulation.generator import generate_all_datasets
from app.detection.engine import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup initialization: prepare directories and ensure demo dataset exists."""
    for d in [settings.DATA_DIR, settings.GENERATED_DIR, settings.UPLOAD_DIR, settings.WATCHED_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    
    # Ensure default dataset is loaded so incidents and threat graph are immediately available
    from app.db.store import store
    from app.api.endpoints import load_dataset
    if not store.incidents:
        try:
            load_dataset(dataset_name="mixed")
        except Exception as e:
            print(f"Dataset auto-load notice: {e}")
    yield


app = FastAPI(
    title="AI-Powered Cyber Threat Intelligence System",
    description="Multi-stage attack chain reconstruction, entity graph correlation, and automated SOAR response.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(api_router)

# Mount static files for UI
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def serve_index():
    """Serve the SOC Dashboard UI."""
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {
        "system": "AI-Powered Cyber Threat Intelligence Platform",
        "status": "online",
        "docs": "/docs",
        "api": "/api/health"
    }
