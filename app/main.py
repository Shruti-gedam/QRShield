"""
QRShield – FastAPI Application Entry Point
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import router
from app.config import settings

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.app_debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("qrshield")


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡  QRShield starting up …")
    # Pre-warm tldextract suffix list (downloads once, cached locally)
    try:
        import tldextract
        tldextract.extract("example.com")
        logger.info("tldextract suffix list ready.")
    except Exception as exc:
        logger.warning("tldextract warm-up failed: %s", exc)
    yield
    logger.info("QRShield shut down.")


# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="QRShield",
    description=(
        "Context-Aware Framework for QR-Based Payment Fraud and Deception Detection. "
        "Rule-based heuristic analysis across payload, URL, and scan context."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request timing middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    response.headers["X-Process-Time-Ms"] = f"{elapsed * 1000:.1f}"
    return response


# ── Static files & templates ──────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(router, prefix="/api")


# ── Root – serve the web UI ───────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_ui(request: Request):
    return templates.TemplateResponse(request, "index.html")
