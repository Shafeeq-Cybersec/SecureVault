"""Typed GitHub client errors, mapped to clear API responses by the router."""

from __future__ import annotations


class GitHubError(Exception):
    """Base class for GitHub client failures. ``status`` is the HTTP status to
    surface to the API caller."""

    status = 502

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class RepoNotFoundError(GitHubError):
    status = 404


class AuthError(GitHubError):
    status = 401


class RateLimitError(GitHubError):
    status = 429

    def __init__(self, message: str, reset_epoch: int | None = None,
                 reset_in_seconds: int | None = None):
        super().__init__(message)
        self.reset_epoch = reset_epoch
        self.reset_in_seconds = reset_in_seconds


class InvalidTargetError(GitHubError):
    status = 400
