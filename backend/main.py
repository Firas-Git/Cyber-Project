from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from database.mongodb import connect_db, close_db
from services.model_service import load_model
from routes import upload, analysis, predict, metrics, auth, history, models
from routes.websocket import router as ws_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    # ── Startup ────────────────────────────────────────────────────────────────
    load_model()
    try:
        await connect_db()
        print("✅ MongoDB connected")
    except Exception as e:
        print(f"⚠️  MongoDB connection failed: {e} — predictions will not be persisted")
    yield
    # ── Shutdown ───────────────────────────────────────────────────────────────
    await close_db()


settings = get_settings()

app = FastAPI(
    title="CyberSec Intrusion Detection API",
    version="2.0.0",
    description="SOC-grade real-time cybersecurity monitoring platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ─────────────────────────────────────────────────────────────────────
app.include_router(auth.router,     prefix="/api/auth",     tags=["Auth"])
app.include_router(upload.router,   prefix="/api/upload",   tags=["Upload"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(predict.router,  prefix="/api/predict",  tags=["Predict"])
app.include_router(metrics.router,  prefix="/api/metrics",  tags=["Metrics"])
app.include_router(history.router,  prefix="/api/history",  tags=["History"])
app.include_router(models.router,   prefix="/api/models",   tags=["Models"])
app.include_router(ws_router,       tags=["WebSocket"])


@app.get("/")
async def root():
    return {"status": "CyberSec AI Backend v2.0 running", "docs": "/docs"}


@app.get("/health")
async def health():
    from services.ws_manager import ws_manager
    return {
        "status": "healthy",
        "active_ws_connections": ws_manager.active_connections,
    }
