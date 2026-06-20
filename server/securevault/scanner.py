"""Apply detection rules to file content, then score each match.

Detection is regex (fast, finds candidates). Classification is multi-signal
(scoring.py) — entropy, file/path/variable context, dummy denylists and
structural validation combine into a confidence score and a finding category.
Severity = impact if real; confidence = likelihood it is real.
"""

from __future__ import annotations

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
    "not a hardcoded credential — most likely safe. Confirm the real value is "
    "injected at runtime from a secret manager or CI secret store, never committed."
)


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
                signals=["Committed environment (.env) file — should never be in a repo"],
                redacted_line=f"<committed environment file: {path}>",
                match_preview="(entire file)",
                remediation=ENV_FILE_RULE.remediation,
            )
        )

    # (line_number, secret_value) -> best Finding (highest severity, then confidence).
    best: dict[tuple[int, str], Finding] = {}

    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                secret = match.group("secret")
                if not secret:
                    continue
                credential = match.group(rule.credential_group) or secret
                var_name = extract_var_name(line, match.start("secret"))

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

                if is_nonsecret_value(credential):
                    # Nothing secret to hide — show the literal so it's reviewable.
                    preview = credential.strip()
                    redacted_line = line.strip()
                    if len(redacted_line) > 200:
                        redacted_line = redacted_line[:200] + "…"
                    remediation = _TEMPLATE_REMEDIATION
                else:
                    redacted = redact_secret(secret)
                    preview = redacted
                    redacted_line = redact_line(line, secret, redacted)
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
                    signals=outcome.signals,
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
