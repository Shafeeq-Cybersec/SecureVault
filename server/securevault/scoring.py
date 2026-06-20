"""Multi-signal confidence scoring.

A regex match only says a value *looks* like a secret. This module combines
several independent signals into a numeric confidence (1-99) and a finding
category, so analysts can prioritise real leaks over template/test/doc noise.

Signals combined:
  * placeholder / env-variable / dummy value detection
  * file-path context (example, test/fixtures, docs/markdown)
  * variable-name context (test_password vs AWS_SECRET_ACCESS_KEY)
  * Shannon entropy of the credential
  * structural format validation (AWS / GitHub / Stripe / Google / JWT)

Severity = impact *if real* (kept from the rule). Confidence = likelihood it
*is* real (computed here). The two are deliberately orthogonal.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field

# ---- finding categories ----------------------------------------------------
CAT_LIKELY = "Likely Secret"
CAT_POTENTIAL = "Potential Secret"
CAT_TEMPLATE = "Example / Template"
CAT_TEST = "Test Credential"
CAT_DOC = "Documentation Sample"

# Categories that mean "almost certainly not a live production secret".
BENIGN_CATEGORIES = {CAT_TEMPLATE, CAT_TEST, CAT_DOC}

WEAK_RULES = {"generic_api_key", "hardcoded_password"}
STRONG_PREFIX_RULES = {
    "aws_access_key_id", "github_pat", "github_fine_grained_pat",
    "google_api_key", "stripe_secret_key", "stripe_publishable_key",
    "slack_token", "private_key",
}

# Starting confidence per rule, reflecting how unique/structured the pattern is.
# High-specificity provider prefixes are very unlikely to match by accident;
# keyword-based rules (generic key / password) are far more prone to noise.
BASE_CONFIDENCE = {
    # Strong structural prefix + exact length — very low FP rate
    "private_key": 92,
    "digitalocean_pat": 92,
    "gitlab_pat": 92,
    "npm_token": 92,
    "pypi_token": 92,
    "aws_access_key_id": 90,
    "github_pat": 90,
    "github_fine_grained_pat": 90,
    "stripe_secret_key": 90,
    "openai_api_key": 90,
    "anthropic_api_key": 90,
    "razorpay_live_key": 90,
    "sendgrid_api_key": 88,
    "shopify_token": 88,
    "google_api_key": 85,
    "huggingface_token": 85,
    "replicate_token": 85,
    "slack_token": 85,
    "square_api_key": 85,
    "mailchimp_api_key": 82,
    "aws_secret_access_key": 80,
    "discord_bot_token": 80,
    "stripe_publishable_key": 80,
    "db_connection_string": 72,
    "jwt": 70,
    "twilio_account_sid": 65,  # AC prefix alone is not uniquely Twilio
    "generic_api_key": 50,
    "hardcoded_password": 50,
}


def base_for(rule_id: str) -> int:
    return BASE_CONFIDENCE.get(rule_id, 55)


@dataclass
class ScoreOutcome:
    confidence: int
    confidence_label: str
    category: str
    severity: str
    suppress: bool = False
    signals: list[str] = field(default_factory=list)


# ---- value classification --------------------------------------------------
_TEMPLATE_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_]\w*|\{\{[^}]+\}\}")
_ANGLE_RE = re.compile(r"<[A-Za-z0-9_ .\-]{2,}>")
_PASSWORD_SEQ_RE = re.compile(r"(?i)^(?:password|passwd|pwd)[0-9!@#]*$")

_PLACEHOLDER_HINTS = (
    "your_", "your-", "yourkey", "your.", "change_me", "changeme", "placeholder",
    "<your", "xxxxx", "redacted", "insert_", "put_your", "add_your", "replace_me",
    "_here", "key_here", "token_here", "todo", "fixme",
)

_DUMMY_EXACT = {
    "password", "passwd", "pwd", "secret", "changeme", "change_me", "test",
    "test123", "testing", "dummy", "example", "sample", "demo", "admin",
    "administrator", "root", "localhost", "foo", "bar", "baz", "foobar",
    "none", "null", "nil", "123456", "12345678", "qwerty", "abc123",
    "letmein", "fakekey", "faketoken", "notreal", "welcome", "guest",
}
_DUMMY_SUBSTRINGS = (
    "example", "sample", "dummy", "fakekey", "faketoken", "notreal",
    "test_key", "test-key", "testkey", "mock_", "_mock", "deadbeef",
)
_COMMON_PASSWORDS = {
    "password123", "password1", "passw0rd", "admin123", "root123",
    "welcome1", "p@ssw0rd", "iloveyou", "1qaz2wsx",
}

_CODE_REF_HINTS = (
    "getenv", "process.env", "os.environ", "environ[", "import.meta.env",
    "config.get", "settings.", "secrets.get",
)


def is_env_template(value: str) -> bool:
    """Variable references: ${VAR}, $VAR, {{ var }}, <API_KEY>. Meaningful — they
    show where a real credential flows, so we surface them (at LOW)."""
    return bool(_TEMPLATE_RE.search(value) or _ANGLE_RE.search(value))


def is_placeholder_hint(value: str) -> bool:
    """Junk placeholders like your_api_key_here / CHANGE_ME / TODO."""
    low = value.strip().lower()
    return any(h in low for h in _PLACEHOLDER_HINTS)


def is_code_reference(value: str) -> bool:
    if "(" in value or ")" in value:
        return True
    low = value.lower()
    return any(h in low for h in _CODE_REF_HINTS)


def is_dummy(value: str) -> bool:
    low = value.strip().lower()
    if low in _DUMMY_EXACT or low in _COMMON_PASSWORDS:
        return True
    if _PASSWORD_SEQ_RE.match(low):
        return True
    return any(sub in low for sub in _DUMMY_SUBSTRINGS)


def is_nonsecret_value(value: str) -> bool:
    """Any value we can show in clear because it isn't a real credential."""
    return (
        is_env_template(value)
        or is_code_reference(value)
        or is_dummy(value)
        or is_placeholder_hint(value)
    )


# ---- path classification ---------------------------------------------------
_TEST_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture",
    "mock", "mocks", "__mocks__", "sample_data", "testdata", "test_data",
    "examples", "e2e", "cypress",
}
_DOC_DIRS = {"docs", "doc", "documentation", "wiki"}
_DOC_EXT = (".md", ".mdx", ".markdown", ".rst", ".adoc", ".txt")


def classify_path(path: str) -> str:
    low = path.lower()
    parts = low.split("/")
    base = parts[-1]
    if re.search(r"\.(example|sample|template|dist|defaults)(\.|$)", base) \
            or "example" in base or "sample" in base or ".template" in base:
        return "example"
    if base.endswith(_DOC_EXT) or any(p in _DOC_DIRS for p in parts):
        return "docs"
    if any(p in _TEST_DIRS for p in parts):
        return "test"
    return "production"


# ---- variable-name classification ------------------------------------------
_DUMMY_NAME_HINTS = (
    "test", "dummy", "example", "sample", "mock", "fake", "placeholder",
    "fixture", "demo", "foo", "bar",
)
_STRONG_NAME_HINTS = (
    "secret", "token", "apikey", "api_key", "password", "passwd",
    "access_key", "private_key", "client_secret", "credential",
)
_IDENT_TAIL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_\-]*)$")


def extract_var_name(line: str, match_start: int) -> str:
    prefix = line[:match_start]
    prefix = re.sub(r"[\"'`\s:=]+$", "", prefix)
    m = _IDENT_TAIL_RE.search(prefix)
    return m.group(1) if m else ""


def classify_var_name(name: str) -> str:
    low = name.lower().replace("-", "_")
    if any(h in low for h in _DUMMY_NAME_HINTS):
        return "dummy"
    if any(h in low for h in _STRONG_NAME_HINTS):
        return "strong"
    return "neutral"


# ---- entropy ---------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Bits of entropy per character (0 = uniform, higher = more random)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---- structural validation -------------------------------------------------
def _valid_jwt(secret: str) -> bool:
    parts = secret.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b))
        return "alg" in header
    except (ValueError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
        return False


def validate_structure(rule_id: str, secret: str) -> bool | None:
    """True/False if the rule has a structural check; None if not applicable."""
    if rule_id == "jwt":
        return _valid_jwt(secret)
    if rule_id == "aws_access_key_id":
        return bool(re.fullmatch(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}", secret))
    if rule_id in ("github_pat", "github_fine_grained_pat"):
        return len(secret) >= 36
    if rule_id == "google_api_key":
        return bool(re.fullmatch(r"AIza[0-9A-Za-z_\-]{35}", secret))
    if rule_id in ("stripe_secret_key", "stripe_publishable_key"):
        return len(secret) >= 24
    if rule_id == "slack_token":
        return bool(re.fullmatch(r"xox[baprs]-[0-9A-Za-z-]{10,}", secret))
    if rule_id == "private_key":
        return True
    return None


def _clamp(v: int, lo: int = 1, hi: int = 99) -> int:
    return max(lo, min(hi, v))


def score_finding(
    *,
    rule_id: str,
    base_confidence: int,
    rule_severity: str,
    secret: str,
    credential: str,
    var_name: str,
    path: str,
    low_severity: str = "LOW",
) -> ScoreOutcome:
    """Combine all signals into a confidence + category + (maybe lowered) severity."""
    weak = rule_id in WEAK_RULES
    cred = credential.strip()

    # --- 1. Non-secret values short-circuit to a low score ------------------
    # The value itself isn't a literal credential, so severity drops to LOW and
    # the score can't be rescued by other signals.
    if is_env_template(cred):
        return ScoreOutcome(
            18, "Low", CAT_TEMPLATE, low_severity, False,
            ["Value is a variable reference (e.g. ${VAR}, <API_KEY>), not a literal"],
        )
    if is_code_reference(cred):
        return ScoreOutcome(
            16, "Low", CAT_TEMPLATE, low_severity, weak,
            ["Value is an env/config lookup, not a hardcoded literal"],
        )
    if is_dummy(cred) or is_placeholder_hint(cred):
        return ScoreOutcome(
            12, "Low", CAT_TEMPLATE, low_severity, weak,
            ['Value is a known dummy / placeholder (e.g. "changeme", "test123")'],
        )

    # --- 2. Real-looking value: combine the remaining signals ---------------
    signals: list[str] = []
    conf = base_confidence
    ceiling = 99  # context can cap confidence; later boosts can't exceed it
    category: str | None = None

    if rule_id in STRONG_PREFIX_RULES:
        signals.append("Matches a high-specificity provider prefix")

    # Path context — caps confidence + categorises, but keeps severity
    # (a real key in tests/ is still critical *if* it is real).
    path_kind = classify_path(path)
    if path_kind == "example":
        signals.append("Located in an example/template file")
        ceiling = min(ceiling, 30)
        category = CAT_DOC
    elif path_kind == "test":
        signals.append("Located in a test/fixtures/mock path")
        ceiling = min(ceiling, 40)
        category = CAT_TEST
    elif path_kind == "docs":
        signals.append("Located in documentation / markdown")
        ceiling = min(ceiling, 38)
        category = CAT_DOC

    # Variable-name context.
    name_kind = classify_var_name(var_name)
    if name_kind == "dummy" and var_name:
        signals.append(f'Variable name suggests a non-secret ("{var_name}")')
        ceiling = min(ceiling, 45)
        category = category or CAT_TEST
    elif name_kind == "strong" and var_name:
        signals.append(f'Variable name matches a known secret ("{var_name}")')
        conf += 5

    # Entropy of the value.
    ent = shannon_entropy(cred)
    if len(cred) >= 16 and ent >= 3.5:
        signals.append(f"High entropy ({ent:.1f} bits/char)")
        conf += 8
    elif ent < 2.5 and weak:
        signals.append(f"Low entropy ({ent:.1f} bits/char) — looks human-written")
        conf -= 18

    # Structural format validation.
    valid = validate_structure(rule_id, secret)
    if valid is True:
        signals.append("Passes provider format validation")
        conf += 8
    elif valid is False:
        signals.append("Fails provider format validation")
        conf -= 25

    conf = _clamp(min(conf, ceiling))
    if category is None:
        category = CAT_LIKELY if conf >= 75 else CAT_POTENTIAL
    label = "High" if conf >= 75 else ("Medium" if conf >= 45 else "Low")

    return ScoreOutcome(
        confidence=conf,
        confidence_label=label,
        category=category,
        severity=rule_severity,
        suppress=False,
        signals=signals,
    )
