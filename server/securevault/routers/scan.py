"""POST /api/scan — scan a GitHub repository for committed secrets."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..errors import GitHubError, RateLimitError
from ..models import ScanRequest, ScanResult
from ..scan_service import scan_repository

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest) -> ScanResult:
    try:
        return await scan_repository(
            target=req.target, token=req.token, max_file_size=req.max_file_size
        )
    except RateLimitError as exc:
        # Surface reset timing in a structured way for the frontend.
        raise HTTPException(
            status_code=exc.status,
            detail={
                "error": "rate_limited",
                "message": exc.message,
                "reset_epoch": exc.reset_epoch,
                "reset_in_seconds": exc.reset_in_seconds,
            },
        ) from exc
    except GitHubError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": exc.__class__.__name__, "message": exc.message},
        ) from exc
