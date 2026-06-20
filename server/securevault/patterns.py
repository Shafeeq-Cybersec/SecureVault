"""Secret detection rules.

Each rule is a compiled regex with a named capture group ``secret`` that isolates
the sensitive value (so redaction targets exactly the secret, not the
surrounding code). Rules carry a severity and type-specific remediation advice.

Severity scale: CRITICAL > HIGH > MEDIUM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    remediation: str
    # Which named group holds the actual credential to confidence-check. Defaults
    # to the whole match; connection strings point it at just the password.
    credential_group: str = "secret"


# NOTE: every pattern MUST expose a (?P<secret>...) group.
RULES: list[Rule] = [
    Rule(
        id="aws_access_key_id",
        name="AWS Access Key ID",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})"),
        remediation=(
            "Deactivate and delete this access key in the AWS IAM console "
            "immediately, rotate to a new key, and prefer IAM roles or "
            "short-lived STS credentials over long-lived keys. Audit CloudTrail "
            "for unauthorized use."
        ),
    ),
    Rule(
        id="aws_secret_access_key",
        name="AWS Secret Access Key",
        severity=CRITICAL,
        # Context-anchored to the aws secret key assignment to avoid matching any
        # random 40-char base64 string.
        pattern=re.compile(
            r"(?i)aws_?secret_?access_?key[\"'\s]*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{40})"
        ),
        remediation=(
            "Treat the paired access key as fully compromised: deactivate it in "
            "IAM, rotate credentials, and remove the secret from git history "
            "(git filter-repo / BFG). Move secrets to AWS Secrets Manager or env "
            "vars, never source."
        ),
    ),
    Rule(
        id="github_pat",
        name="GitHub Personal Access Token",
        severity=CRITICAL,
        # ghp_ (classic PAT), gho_ (OAuth), ghu_ (user-to-server),
        # ghs_ (server-to-server), ghr_ (refresh).
        pattern=re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9]{36,255})"),
        remediation=(
            "Revoke the token at github.com/settings/tokens right now, then issue "
            "a new fine-grained token with least privilege. Store it in CI secrets "
            "or a secret manager, never in code."
        ),
    ),
    Rule(
        id="github_fine_grained_pat",
        name="GitHub Fine-Grained PAT",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>github_pat_[A-Za-z0-9_]{22,255})"),
        remediation=(
            "Revoke this fine-grained token in GitHub settings immediately and "
            "reissue with minimal repository and permission scope."
        ),
    ),
    Rule(
        id="openai_api_key",
        name="OpenAI API Key",
        severity=CRITICAL,
        # Legacy keys: sk-[48 alphanum]
        # Project keys: sk-proj-[40+ alphanum/dash/underscore]
        # Service-account keys: sk-svcacct-[40+]
        pattern=re.compile(
            r"(?P<secret>sk-(?:proj-|svcacct-)?[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"
            r"|sk-proj-[A-Za-z0-9_\-]{40,}"
            r"|sk-svcacct-[A-Za-z0-9_\-]{40,})"
        ),
        remediation=(
            "Revoke this key immediately at platform.openai.com/api-keys. "
            "Generate a replacement, store it in an environment variable or secret "
            "manager, and purge the exposed key from git history with git-filter-repo."
        ),
    ),
    # ── Additional AI / ML services ──────────────────────────────────────────
    Rule(
        id="anthropic_api_key",
        name="Anthropic API Key",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>sk-ant-[A-Za-z0-9_\-]{20,})"),
        remediation=(
            "Rotate the key immediately at console.anthropic.com/settings/keys. "
            "Store it in an environment variable or secret manager, never in source."
        ),
    ),
    Rule(
        id="huggingface_token",
        name="Hugging Face Token",
        severity=HIGH,
        pattern=re.compile(r"(?P<secret>hf_[A-Za-z0-9]{20,})"),
        remediation=(
            "Revoke the token at huggingface.co/settings/tokens and generate a "
            "replacement with the minimum required scope (read vs. write vs. admin)."
        ),
    ),
    Rule(
        id="replicate_token",
        name="Replicate API Token",
        severity=HIGH,
        pattern=re.compile(r"(?P<secret>r8_[A-Za-z0-9]{40})"),
        remediation=(
            "Delete the token at replicate.com/account/api-tokens and create a "
            "replacement. Leaked tokens accrue inference charges on your account."
        ),
    ),
    # ── Cloud providers ───────────────────────────────────────────────────────
    Rule(
        id="digitalocean_pat",
        name="DigitalOcean Personal Access Token",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>dop_v1_[a-f0-9]{64})"),
        remediation=(
            "Revoke the token in the DigitalOcean control panel under "
            "API > Tokens/Keys immediately — it grants full account access."
        ),
    ),
    # ── Communication / SaaS ─────────────────────────────────────────────────
    Rule(
        id="sendgrid_api_key",
        name="SendGrid API Key",
        severity=HIGH,
        pattern=re.compile(
            r"(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"
        ),
        remediation=(
            "Delete the key in the SendGrid dashboard under Settings > API Keys "
            "and issue a replacement. A full-access key lets anyone send email as you."
        ),
    ),
    Rule(
        id="twilio_account_sid",
        name="Twilio Account SID",
        severity=HIGH,
        pattern=re.compile(r"(?P<secret>AC[a-f0-9]{32})"),
        remediation=(
            "A Twilio Account SID alone is not enough for API access, but its "
            "presence strongly suggests a paired Auth Token is nearby. Rotate Auth "
            "Tokens in the Twilio Console and audit surrounding code immediately."
        ),
    ),
    Rule(
        id="discord_bot_token",
        name="Discord Bot Token",
        severity=HIGH,
        pattern=re.compile(
            r"(?i)(?:discord[_\-. ]?(?:bot[_\-. ]?)?token|bot[_\-. ]?token)"
            r"[\"'\s]*[:=]\s*[\"']"
            r"(?P<secret>[A-Za-z0-9_\-]{24,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,})"
            r"[\"']"
        ),
        remediation=(
            "Regenerate the token in the Discord Developer Portal under your "
            "application's Bot settings. Anyone with this token has full bot control."
        ),
    ),
    Rule(
        id="mailchimp_api_key",
        name="Mailchimp API Key",
        severity=MEDIUM,
        pattern=re.compile(r"(?P<secret>[a-f0-9]{32}-us\d{1,2})"),
        remediation=(
            "Revoke the key in Mailchimp under Account > Extras > API Keys and "
            "generate a replacement. A leaked key exposes your full subscriber list."
        ),
    ),
    # ── DevOps / package registries ───────────────────────────────────────────
    Rule(
        id="gitlab_pat",
        name="GitLab Personal Access Token",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>glpat-[A-Za-z0-9_\-]{20})"),
        remediation=(
            "Revoke the token immediately at gitlab.com/-/profile/personal_access_tokens "
            "and issue a replacement with minimum required scope."
        ),
    ),
    Rule(
        id="npm_token",
        name="npm Access Token",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>npm_[A-Za-z0-9]{36})"),
        remediation=(
            "Revoke the token at npmjs.com/settings/<user>/tokens immediately. "
            "A leaked publish token enables supply-chain attacks via malicious package versions."
        ),
    ),
    Rule(
        id="pypi_token",
        name="PyPI API Token",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>pypi-[A-Za-z0-9_\-]{32,})"),
        remediation=(
            "Revoke the token at pypi.org/manage/account/ immediately. "
            "A leaked PyPI token enables supply-chain attacks on Python package consumers."
        ),
    ),
    # ── E-commerce / payments ─────────────────────────────────────────────────
    Rule(
        id="shopify_token",
        name="Shopify Access Token",
        severity=HIGH,
        pattern=re.compile(r"(?P<secret>shp(?:pa|ss|ca|at)_[a-fA-F0-9]{32})"),
        remediation=(
            "Revoke the token in the Shopify Partner Dashboard or store admin "
            "under Apps > Manage private apps and issue a replacement."
        ),
    ),
    Rule(
        id="square_api_key",
        name="Square API Key / OAuth Token",
        severity=HIGH,
        pattern=re.compile(
            r"(?P<secret>(?:sq0atp|sq0csp)-[0-9A-Za-z\-_]{22,43}"
            r"|EAAAl[0-9A-Za-z_\-]{60})"
        ),
        remediation=(
            "Revoke the key in the Square Developer Dashboard under "
            "Applications > Credentials and generate a replacement."
        ),
    ),
    Rule(
        id="razorpay_live_key",
        name="Razorpay Live API Key",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>rzp_live_[A-Za-z0-9]{14})"),
        remediation=(
            "Regenerate the key in the Razorpay Dashboard under Settings > API Keys. "
            "A live key can initiate and manage real payment transactions."
        ),
    ),
    Rule(
        id="google_api_key",
        name="Google API Key",
        severity=HIGH,
        pattern=re.compile(r"(?P<secret>AIza[0-9A-Za-z_\-]{35})"),
        remediation=(
            "Regenerate the key in Google Cloud Console > APIs & Services > "
            "Credentials, and restrict it by API, HTTP referrer, or IP. Delete the "
            "exposed key."
        ),
    ),
    Rule(
        id="stripe_secret_key",
        name="Stripe Secret Key (live)",
        severity=CRITICAL,
        pattern=re.compile(r"(?P<secret>sk_live_[0-9a-zA-Z]{16,})"),
        remediation=(
            "Roll the key in the Stripe Dashboard > Developers > API keys "
            "immediately — a live secret key can move real money. Review recent "
            "charges/refunds for abuse."
        ),
    ),
    Rule(
        id="stripe_publishable_key",
        name="Stripe Publishable Key (live)",
        severity=MEDIUM,
        pattern=re.compile(r"(?P<secret>pk_live_[0-9a-zA-Z]{16,})"),
        remediation=(
            "Publishable keys are meant to be public, but their presence confirms "
            "a live Stripe integration. Confirm no secret key sits alongside it and "
            "that webhook signing secrets are protected."
        ),
    ),
    Rule(
        id="slack_token",
        name="Slack Token",
        severity=HIGH,
        pattern=re.compile(r"(?P<secret>xox[baprs]-[0-9A-Za-z-]{10,})"),
        remediation=(
            "Revoke the token in the Slack app's OAuth settings and reinstall the "
            "app to mint a fresh one. Store it in a secret manager."
        ),
    ),
    Rule(
        id="private_key",
        name="Private Key",
        severity=CRITICAL,
        pattern=re.compile(
            r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
        ),
        remediation=(
            "Consider the key pair compromised: revoke/rotate it everywhere it is "
            "trusted (servers, CAs, deploy keys), generate a new key, and purge the "
            "key from git history."
        ),
    ),
    Rule(
        id="jwt",
        name="JSON Web Token (JWT)",
        severity=HIGH,
        pattern=re.compile(
            r"(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
        ),
        remediation=(
            "If this is a live session/access token, invalidate it (rotate the "
            "signing secret or revoke the session). Never commit JWTs; treat the "
            "signing key as the real secret and keep it server-side."
        ),
    ),
    Rule(
        id="db_connection_string",
        name="Database Connection String with Credentials",
        severity=HIGH,
        pattern=re.compile(
            r"(?i)(?P<secret>(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|jdbc:[a-z0-9]+)"
            r"://[^\s:@/]+:(?P<cred>[^\s:@/]+)@[^\s\"'<>]+)"
        ),
        credential_group="cred",
        remediation=(
            "Rotate the database password immediately and move the connection "
            "string to an environment variable / secret manager. Restrict the DB "
            "user's privileges and network access."
        ),
    ),
    Rule(
        id="generic_api_key",
        name="Generic API Key",
        severity=MEDIUM,
        # Requires an explicit api key assignment with a quoted value.
        pattern=re.compile(
            r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|secret[_-]?key)"
            r"[\"'\s]*[:=]\s*[\"'](?P<secret>[A-Za-z0-9._\-]{16,})[\"']"
        ),
        remediation=(
            "Rotate this credential with its provider and move it out of source "
            "into an environment variable or secret manager. Add the file to "
            ".gitignore if appropriate."
        ),
    ),
    Rule(
        id="hardcoded_password",
        name="Hardcoded Password",
        severity=MEDIUM,
        # Quoted value after password/passwd/pwd assignment.
        pattern=re.compile(
            r"(?i)(?:password|passwd|pwd)[\"'\s]*[:=]\s*[\"'](?P<secret>[^\"']{4,})[\"']"
        ),
        remediation=(
            "Remove the hardcoded password, rotate it, and load it from an "
            "environment variable or secret manager at runtime. Purge it from git "
            "history."
        ),
    ),
]


# A repo file that is itself a committed secrets file (.env). Handled separately
# from line-regex rules because it is path-based, not content-based.
ENV_FILE_RULE = Rule(
    id="committed_env_file",
    name="Committed .env File",
    severity=HIGH,
    pattern=re.compile(r"(?P<secret>.*)"),  # unused; path-based detection
    remediation=(
        "A .env file containing environment secrets should never be committed. "
        "Remove it from the repo, add it to .gitignore, rotate every value it "
        "held, and purge it from git history."
    ),
)
