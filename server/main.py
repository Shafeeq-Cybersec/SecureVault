"""SecureVault backend: FastAPI entrypoint."""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from securevault.routers import scan as scan_router

app = FastAPI(title="SecureVault API", version="0.1.0")

# In production set CORS_ORIGINS to your Vercel URL, e.g.:
#   CORS_ORIGINS=https://securevault.vercel.app
# Multiple origins are comma-separated.
_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
ALLOWED_ORIGINS = [o.strip() for o in _raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    """Lightweight liveness probe."""
    return {"status": "ok"}


@app.get("/api/hello")
def hello() -> dict:
    """Hello-world endpoint the frontend calls on load to confirm the link."""
    return {"message": "Hello from SecureVault FastAPI backend 👋"}


# Secrets scanning routes.
app.include_router(scan_router.router)
