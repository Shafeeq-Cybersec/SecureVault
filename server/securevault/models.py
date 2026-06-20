"""API request/response schemas."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Finding(BaseModel):
    file_path: str
    line_number: int
    secret_type: str
    rule_id: str
    severity: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW. Impact if real.")
    confidence: int = Field(
        description="0-99 likelihood this is a real, live secret (multi-signal score)"
    )
    confidence_label: str = Field(description="High | Medium | Low")
    category: str = Field(
        description="Likely Secret | Potential Secret | Example / Template | "
        "Test Credential | Documentation Sample"
    )
    signals: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons that produced the confidence score",
    )
    redacted_line: str = Field(description="Source line with the secret masked")
    match_preview: str = Field(description="Redacted secret: first 6 + mask + last 4")
    remediation: str


class RateLimitInfo(BaseModel):
    limit: int | None = None
    remaining: int | None = None
    reset_epoch: int | None = None
    reset_in_seconds: int | None = None


class ScanRequest(BaseModel):
    target: str = Field(description="owner/repo or a github.com repo URL")
    token: str | None = Field(
        default=None,
        description="Optional GitHub token; lifts rate limit to 5000/hr and "
        "enables private-repo scanning. Never stored.",
    )
    max_file_size: int | None = Field(
        default=None, description="Override the per-file size cap in bytes"
    )


class ScanResult(BaseModel):
    repository: str
    branch: str
    files_scanned: int
    files_skipped: int
    total_findings: int
    severity_counts: dict[str, int]
    category_counts: dict[str, int] = {}
    findings: list[Finding]
    rate_limit: RateLimitInfo
    partial: bool = Field(
        default=False,
        description="True if the scan stopped early (e.g. rate limit) and results "
        "are incomplete",
    )
    errors: list[str] = []
    tree_truncated: bool = Field(
        default=False,
        description="True if the repo is too large for GitHub to return the full "
        "file tree in one response",
    )
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
