"""Rate-limit-aware GitHub REST client (httpx).

Enumerates a repo's files recursively via the Git Trees API (one request,
``recursive=1``) and fetches each text file through the Contents API. Every
response updates the tracked rate-limit state, and quota/auth/not-found
conditions raise typed errors with actionable messages.
"""

from __future__ import annotations

import base64
import re
import time
from types import TracebackType

import httpx

from .config import GITHUB_API, REQUEST_TIMEOUT, USER_AGENT
from .errors import (
    AuthError,
    GitHubError,
    InvalidTargetError,
    RateLimitError,
    RepoNotFoundError,
)

_TARGET_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:github\.com/)?(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)


def parse_target(target: str) -> tuple[str, str]:
    """Parse 'owner/repo' or a github.com URL into (owner, repo)."""
    target = (target or "").strip()
    match = _TARGET_RE.match(target)
    if not match:
        raise InvalidTargetError(
            f"Could not parse '{target}'. Use 'owner/repo' or a github.com repo URL."
        )
    return match.group("owner"), match.group("repo")


class RateLimitState:
    def __init__(self) -> None:
        self.limit: int | None = None
        self.remaining: int | None = None
        self.reset_epoch: int | None = None

    @property
    def reset_in_seconds(self) -> int | None:
        if self.reset_epoch is None:
            return None
        return max(0, int(self.reset_epoch - time.time()))


class GitHubClient:
    def __init__(self, token: str | None = None):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=GITHUB_API, headers=headers, timeout=REQUEST_TIMEOUT
        )
        self.rate_limit = RateLimitState()

    async def __aenter__(self) -> "GitHubClient":
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None,
                        exc: BaseException | None,
                        tb: TracebackType | None) -> None:
        await self._client.aclose()

    # -- internals -------------------------------------------------------

    def _update_rate_limit(self, resp: httpx.Response) -> None:
        h = resp.headers
        if "x-ratelimit-limit" in h:
            self.rate_limit.limit = int(h["x-ratelimit-limit"])
        if "x-ratelimit-remaining" in h:
            self.rate_limit.remaining = int(h["x-ratelimit-remaining"])
        if "x-ratelimit-reset" in h:
            self.rate_limit.reset_epoch = int(h["x-ratelimit-reset"])

    def _raise_rate_limited(self, resp: httpx.Response) -> None:
        reset = self.rate_limit.reset_epoch
        wait = self.rate_limit.reset_in_seconds
        retry_after = resp.headers.get("retry-after")
        if retry_after and retry_after.isdigit():
            wait = int(retry_after)
        scope = "authenticated (5000/hr)" if "authorization" in {
            k.lower() for k in self._client.headers
        } else "unauthenticated (60/hr)"
        mins = f"~{wait // 60}m {wait % 60}s" if wait is not None else "unknown"
        raise RateLimitError(
            f"GitHub API rate limit exceeded on the {scope} quota. "
            f"Resets in {mins}. Provide a GitHub token (or wait) and retry.",
            reset_epoch=reset,
            reset_in_seconds=wait,
        )

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        try:
            resp = await self._client.get(path, params=params)
        except httpx.RequestError as exc:
            raise GitHubError(f"Network error contacting GitHub: {exc}") from exc

        self._update_rate_limit(resp)

        if resp.status_code == 200:
            return resp
        if resp.status_code == 401:
            raise AuthError("GitHub rejected the token (401). Check it is valid and unexpired.")
        if resp.status_code == 404:
            raise RepoNotFoundError(
                "Repository not found (404). Check owner/repo spelling, and supply "
                "a token if it is private."
            )
        if resp.status_code in (403, 429):
            remaining = self.rate_limit.remaining
            if remaining == 0 or "rate limit" in resp.text.lower() or "retry-after" in resp.headers:
                self._raise_rate_limited(resp)
            raise AuthError(
                "GitHub returned 403 (forbidden). The token may lack the required "
                "scope for this repository."
            )
        raise GitHubError(
            f"Unexpected GitHub response {resp.status_code}: {resp.text[:200]}"
        )

    # -- public API ------------------------------------------------------

    async def get_default_branch(self, owner: str, repo: str) -> str:
        resp = await self._get(f"/repos/{owner}/{repo}")
        return resp.json().get("default_branch", "main")

    async def list_tree(self, owner: str, repo: str, branch: str) -> tuple[list[dict], bool]:
        """Return (blob entries, truncated). Each entry has path/size/sha."""
        resp = await self._get(
            f"/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"}
        )
        data = resp.json()
        blobs = [e for e in data.get("tree", []) if e.get("type") == "blob"]
        return blobs, bool(data.get("truncated"))

    async def get_file_text(self, owner: str, repo: str, path: str, ref: str) -> str | None:
        """Fetch a file via the Contents API and return decoded UTF-8 text.

        Returns None for binary/undecodable content or blobs GitHub won't inline.
        """
        resp = await self._get(
            f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref}
        )
        data = resp.json()
        if data.get("encoding") != "base64" or not data.get("content"):
            return None
        try:
            raw = base64.b64decode(data["content"])
            return raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None  # binary or non-UTF-8 file
