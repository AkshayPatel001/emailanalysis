"""
FastAPI application entry point.
Configures CORS, lifespan events, error handlers, and route registration.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import init_db, close_db
from app.utils.logger import setup_logging

# Setup structured logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    logger.info("Starting Email Analysis Tool API")
    await init_db()
    logger.info("Database initialized")

    from app.database import async_session_factory
    from app.engines.yara_engine import yara_engine
    async with async_session_factory() as session:
        await yara_engine.reload_rules(session)

    yield
    await close_db()
    logger.info("Application shutdown complete")


app = FastAPI(
    title="Email Analysis Tool",
    description="Professional-grade email analysis for SOC investigations",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Global Exception Handlers ---

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    logger.warning(f"ValueError: {exc}", extra={"path": request.url.path})
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc), "error_type": "validation_error"},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True, extra={"path": request.url.path})
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error_type": "server_error"},
    )


# --- Register API Routers ---

from app.api.analysis import router as analysis_router
from app.api.reports import router as reports_router
from app.api.cases import router as cases_router
from app.api.threat_intel import router as threat_intel_router
from app.api.settings import router as settings_router
from app.api.yara import router as yara_router
from app.api.remediation import router as remediation_router

app.include_router(analysis_router, prefix="/api", tags=["Analysis"])
app.include_router(reports_router, prefix="/api", tags=["Reports"])
app.include_router(cases_router, prefix="/api", tags=["Cases"])
app.include_router(threat_intel_router, prefix="/api", tags=["Threat Intelligence"])
app.include_router(settings_router, prefix="/api", tags=["Settings"])
app.include_router(yara_router, prefix="/api/yara", tags=["YARA"])
app.include_router(remediation_router, prefix="/api/remediation", tags=["Remediation"])


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}
