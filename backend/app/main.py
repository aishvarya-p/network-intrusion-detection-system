"""
FastAPI Application Entry Point for Network Intrusion Detection System (NIDS).
Configures CORS, lifespan events (database & model pre-loading), and API routes.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.database import init_db
from backend.app.api.dependencies import get_detector
from backend.app.api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown events:
    - Creates database tables if not existing.
    - Loads or pre-trains the ML Isolation Forest model.
    """
    print("[NIDS Backend] Initializing SQLite database...")
    init_db()

    print("[NIDS Backend] Loading ML anomaly detection model...")
    detector = get_detector()
    print(f"[NIDS Backend] ML Detector ready (Trained sample count: {detector.training_sample_count})")

    yield

    print("[NIDS Backend] Shutting down NIDS backend service.")


# Initialize FastAPI application
app = FastAPI(
    title="NIDS — Network Intrusion Detection System API",
    description=(
        "AI-Powered Network Security Monitoring Backend. "
        "Provides REST APIs for traffic simulation, CSV dataset ingestion, "
        "Isolation Forest anomaly scoring, and Security Operations Center (SOC) telemetry."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Configuration: Restrict to local frontend origins for defensive security
ALLOWED_ORIGINS = [
    "http://localhost:5173",  # Standard Vite React dev server
    "http://127.0.0.1:5173",
    "http://localhost:3000",  # Alternative React dev port
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Defensive security error handler:
    Prevents leaking internal stack traces or database schema details to clients.
    """
    # Log the real error to server console for debugging
    print(f"[ERROR] Unhandled exception on {request.method} {request.url.path}: {str(exc)}")

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred during request processing. Please consult server logs."
        }
    )


# Mount routes at root and /api for flexible client consumption
app.include_router(router)
app.include_router(router, prefix="/api")


@app.get("/", tags=["System"], summary="API Root Redirect to Docs")
def root():
    return {
        "message": "NIDS (Network Intrusion Detection System) API is running.",
        "documentation": "/docs",
        "health": "/health",
        "api_prefix": "/api"
    }
