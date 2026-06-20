"""Secret redaction helpers.

A detected secret is never returned in full. We keep only the first 6 and last
4 characters of the actual secret value, masking the middle. Short values are
masked entirely so we never expose a usable fraction of a tiny token.
"""

from .config import MAX_LINE_LENGTH

# How many of the masked middle characters to actually print, so a 3 KB private
# key or long JWT doesn't render as a wall of asterisks.
_MAX_MASK = 12


def redact_secret(secret: str) -> str:
    """Return a redacted preview: first 6 + mask + last 4."""
    s = secret.strip()
    n = len(s)
    if n <= 10:
        return "*" * n
    mask = "*" * min(n - 10, _MAX_MASK)
    return f"{s[:6]}{mask}{s[-4:]}"


def redact_line(line: str, secret: str, redacted: str) -> str:
    """Return the source line with the secret value swapped for its redaction.

    The line is trimmed of surrounding whitespace and truncated so a single
    huge line can't bloat the response.
    """
    cleaned = line.strip()
    out = cleaned.replace(secret, redacted, 1)
    # Also handle the case where the matched secret was itself whitespace-padded.
    if out == cleaned and secret.strip() in cleaned:
        out = cleaned.replace(secret.strip(), redacted, 1)
    if len(out) > 200:
        out = out[:200] + "…"
    return out
