"""File-path filtering: decide what's worth fetching and scanning."""

from __future__ import annotations

import os

from .config import BINARY_EXTENSIONS, SKIP_DIRS, SKIP_FILENAMES

# .env variants that are placeholders, not real secret files.
_ENV_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def is_binary_path(path: str) -> bool:
    """True if the extension marks a non-text/binary file."""
    name = _basename(path).lower()
    _, ext = os.path.splitext(name)
    if ext in BINARY_EXTENSIONS:
        return True
    # Minified bundles: noisy, huge, low signal.
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    return False


def should_skip_path(path: str) -> bool:
    """True if this path lives in a skipped directory or is a skipped file."""
    parts = path.split("/")
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return True
    if _basename(path).lower() in SKIP_FILENAMES:
        return True
    if is_binary_path(path):
        return True
    return False


def is_env_file(path: str) -> bool:
    """True if the path is a real committed .env secrets file (not an example)."""
    name = _basename(path).lower()
    if name == ".env":
        return True
    if name.startswith(".env.") and not name.endswith(_ENV_SAFE_SUFFIXES):
        return True
    return False
