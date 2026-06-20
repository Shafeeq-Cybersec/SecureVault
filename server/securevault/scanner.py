"""Apply detection rules to file content, then score each match.

Detection is regex (fast, finds candidates). Classification is multi-signal
(scoring.py): entropy, file/path/variable context, dummy denylists and
structural validation combine into a confidence score and a finding category.
Severity = impact if real; confidence = likelihood it is real.

Evasion handling:
  - String concatenation: "abc" + "def" and "abc" "def" are collapsed before
    scanning so split secrets like "AIza" + "Sy1234..." are caught.
  - Base64 encoding: long base64 literals are decoded and the result is scanned,
    catching secrets stored as encoded strings to fool simple scanners.
"""

from __future__ import annotations

import base64 as _b64
import re

from .config import MAX_LINE_LENGTH
from .filters import is_env_file
from .models import Finding
from .patterns import ENV_FILE_RULE, RULES, SEVERITY_ORDER
from .redaction import redact_line, redact_secret
from .scoring import (
    base_for,
    extract_var_name,
    is_nonsecret_value,
    score_finding,
    CAT_LIKELY,
)

_TEMPLATE_REMEDIATION = (
    "This value references environment/shell variables or is a known placeholder, "
    "not a hardcoded credential. Most likely safe. Confirm the real value is "
    "injected at runtime from a secret manager or CI secret store, never committed."
)

# ── Evasion-aware preprocessing ───────────────────────────────────────────────

# Matches two adjacent/concatenated quoted string literals.
# Handles: "a"+"b", "a" + "b", "a" "b", 'a'+'b', mixed quotes.
_CONCAT_RE = re.compile(
    r'(?P<q1>["\'])(?P<s1>[^"\'\\]*)(?P=q1)'
    r'\s*(?:\+\s*)?'
    r'(?P<q2>["\'])(?P<s2>[^"\'\\]*)(?P=q2)'
)

_B64_RE = re.compile(r'["\']([A-Za-z0-9+/]{32,}={0,2})["\']')


def _collapse_concat(line: str) -> str:
    """Collapse 'a'+'b' and 'a' 'b' into a single 'ab', applied repeatedly."""
    prev, result = None, line
    while result != prev:
        prev = result
        result = _CONCAT_RE.sub(
            lambda m: f'"{m.group("s1")}{m.group("s2")}"', result
        )
    return result


def _b64_variants(line: str) -> list[str]:
    """Decode base64 string literals and return alternative line versions."""
    variants: list[str] = []
    for m in _B64_RE.finditer(line):
        try:
            decoded = _b64.b64decode(m.group(1)).decode("utf-8")
        except Exception:
            continue
        if decoded.isprintable() and len(decoded) >= 8:
            variants.append(line[: m.start(1)] + decoded + line[m.end(1) :])
    return variants


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_text(path: str, text: str) -> list[Finding]:
    """Scan a single file's text, returning scored, redacted findings."""
    findings: list[Finding] = []

    # Path-based rule: a committed .env file (examples already excluded upstream).
    if is_env_file(path):
        findings.append(
            Finding(
                file_path=path,
                line_number=1,
                secret_type=ENV_FILE_RULE.name,
                rule_id=ENV_FILE_RULE.id,
                severity=ENV_FILE_RULE.severity,
                confidence=80,
                confidence_label="High",
                category=CAT_LIKELY,
                signals=["Committed environment (.env) file. Should never be in a repo."],
                redacted_line=f"<committed environment file: {path}>",
                match_preview="(entire file)",
                remediation=ENV_FILE_RULE.remediation,
            )
        )

    # (line_number, secret_value) -> best Finding (highest severity, then confidence).
    best: dict[tuple[int, str], Finding] = {}

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        if len(raw_line) > MAX_LINE_LENGTH:
            continue

        # Each candidate: (line_to_scan, line_to_display, extra_signals)
        candidates: list[tuple[str, str, list[str]]] = [(raw_line, raw_line, [])]

        collapsed = _collapse_concat(raw_line)
        if collapsed != raw_line:
            candidates.append((
                collapsed, collapsed,
                ["string concatenation: secret was split across literals"],
            ))

        for b64_line in _b64_variants(raw_line):
            candidates.append((
                b64_line, b64_line,
                ["base64-encoded secret: decoded value matched a known pattern"],
            ))

        for scan_line, display_line, extra_signals in candidates:
            for rule in RULES:
                for match in rule.pattern.finditer(scan_line):
                    secret = match.group("secret")
                    if not secret:
                        continue
                    credential = match.group(rule.credential_group) or secret
                    var_name = extract_var_name(scan_line, match.start("secret"))

                    outcome = score_finding(
                        rule_id=rule.id,
                        base_confidence=base_for(rule.id),
                        rule_severity=rule.severity,
                        secret=secret,
                        credential=credential,
                        var_name=var_name,
                        path=path,
                    )
                    if outcome.suppress:
                        continue

                    all_signals = outcome.signals + extra_signals

                    if is_nonsecret_value(credential):
                        preview = credential.strip()
                        redacted_line = display_line.strip()
                        if len(redacted_line) > 200:
                            redacted_line = redacted_line[:200] + "…"
                        remediation = _TEMPLATE_REMEDIATION
                    else:
                        redacted = redact_secret(secret)
                        preview = redacted
                        redacted_line = redact_line(display_line, secret, redacted)
                        remediation = rule.remediation

                    finding = Finding(
                        file_path=path,
                        line_number=lineno,
                        secret_type=rule.name,
                        rule_id=rule.id,
                        severity=outcome.severity,
                        confidence=outcome.confidence,
                        confidence_label=outcome.confidence_label,
                        category=outcome.category,
                        signals=all_signals,
                        redacted_line=redacted_line,
                        match_preview=preview,
                        remediation=remediation,
                    )

                    key = (lineno, secret)
                    existing = best.get(key)
                    if existing is None or _is_better(finding, existing):
                        best[key] = finding

    findings.extend(best.values())
    findings.sort(
        key=lambda f: (f.line_number, -SEVERITY_ORDER[f.severity], -f.confidence)
    )
    return findings


def _is_better(new: Finding, old: Finding) -> bool:
    if SEVERITY_ORDER[new.severity] != SEVERITY_ORDER[old.severity]:
        return SEVERITY_ORDER[new.severity] > SEVERITY_ORDER[old.severity]
    return new.confidence > old.confidence
