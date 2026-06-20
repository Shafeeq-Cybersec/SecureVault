"""Orchestrates a full repository scan: enumerate -> filter -> fetch -> scan."""

from __future__ import annotations

import asyncio

from .config import CONCURRENCY, MAX_FILE_SIZE
from .errors import RateLimitError
from .filters import should_skip_path
from .github_client import GitHubClient, parse_target
from .models import Finding, RateLimitInfo, ScanResult
from .patterns import SEVERITY_ORDER
from .scanner import scan_text


async def _scan_one(
    gh: GitHubClient,
    owner: str,
    repo: str,
    branch: str,
    path: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    async with sem:
        text = await gh.get_file_text(owner, repo, path, branch)
    if not text:
        return []
    return scan_text(path, text)


async def scan_repository(
    target: str,
    token: str | None = None,
    max_file_size: int | None = None,
) -> ScanResult:
    owner, repo = parse_target(target)
    size_cap = max_file_size or MAX_FILE_SIZE
    errors: list[str] = []

    async with GitHubClient(token) as gh:
        branch = await gh.get_default_branch(owner, repo)
        blobs, truncated = await gh.list_tree(owner, repo, branch)

        candidates = [
            b for b in blobs
            if not should_skip_path(b["path"]) and (b.get("size") or 0) <= size_cap
        ]
        files_skipped = len(blobs) - len(candidates)

        sem = asyncio.Semaphore(CONCURRENCY)
        tasks = [
            _scan_one(gh, owner, repo, branch, b["path"], sem) for b in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        files_scanned = 0
        partial = False
        for outcome in results:
            if isinstance(outcome, RateLimitError):
                partial = True
                if outcome.message not in errors:
                    errors.append(outcome.message)
                continue
            if isinstance(outcome, Exception):
                errors.append(str(outcome))
                continue
            files_scanned += 1
            findings.extend(outcome)

        rate = RateLimitInfo(
            limit=gh.rate_limit.limit,
            remaining=gh.rate_limit.remaining,
            reset_epoch=gh.rate_limit.reset_epoch,
            reset_in_seconds=gh.rate_limit.reset_in_seconds,
        )

    if partial:
        errors.append(
            f"Scan incomplete: {len(candidates) - files_scanned} file(s) were not "
            "fetched due to rate limiting."
        )

    # Sort findings: most severe first, then by file/line.
    findings.sort(
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.file_path, f.line_number)
    )
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    return ScanResult(
        repository=f"{owner}/{repo}",
        branch=branch,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        total_findings=len(findings),
        severity_counts=severity_counts,
        category_counts=category_counts,
        findings=findings,
        rate_limit=rate,
        partial=partial,
        errors=errors,
        tree_truncated=truncated,
    )
