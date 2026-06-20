"""Detection tests using fake, invalid secrets — no network involved.

Every credential below is syntactically shaped like the real thing but is not a
live secret. The goal is to prove each detector fires, redaction hides the value,
and obvious placeholders are suppressed.
"""

from securevault.github_client import parse_target
from securevault.redaction import redact_secret
from securevault.scanner import scan_text

# One line per secret type. Keywords are chosen so each line triggers exactly
# the intended rule.
SAMPLE = '''\
AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
aws_secret_access_key = "abcd1234EFGH5678ijkl9012MNOP3456qrst7890"
token = "ghp_012345678901234567890123456789abcdef"
oauth = "gho_abcdefABCDEF0123456789abcdefABCDEF12"
userauth = "ghu_ABCDEF0123456789abcdefABCDEF01234567"
api_key = "abcdef0123456789ABCDEF"
password = "S3cr3tP@ssw0rd!"
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV5adQssw5c"
-----BEGIN RSA PRIVATE KEY-----
STRIPE = "sk_live_0123456789abcdefABCDEFgh"
STRIPEPUB = "pk_live_0123456789abcdefABCDEFij"
SLACK = "xoxb-1234567890-0987654321-abcdEFGHijklmnopQRSTuvwx"
GOOGLE = "AIza012345678901234567890123456789abcde"
DATABASE_URL = "postgres://app_user:Sup3rS3cret@prod-db.internal:5432/appdb"
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH"
REPLICATE_API_TOKEN = "r8_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
DO_PAT = "dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SENDGRID_API_KEY = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
TWILIO_SID = "AC1234567890abcdef1234567890abcdef"
discord_bot_token = "NTk3MDMwNDQxNzkwMzYwNjU2.Xab12a.ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"
MAILCHIMP_KEY = "abcdef0123456789abcdef0123456789-us1"
GITLAB_TOKEN = "glpat-abcdefghijklmnopqrst"
NPM_TOKEN = "npm_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
PYPI_TOKEN = "pypi-abcdefghijklmnopqrstuvwxyzABCDEF"
SHOPIFY_TOKEN = "shppa_abcdef0123456789ABCDEF0123456789"
SQUARE_TOKEN = "sq0atp-abcdefghijklmnopqrstu1"
RAZORPAY_KEY = "rzp_live_abcdefghijklmn"
'''

EXPECTED_RULE_IDS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "github_pat",
    "generic_api_key",
    "hardcoded_password",
    "jwt",
    "private_key",
    "stripe_secret_key",
    "stripe_publishable_key",
    "slack_token",
    "google_api_key",
    "db_connection_string",
    # AI / ML
    "openai_api_key",
    "anthropic_api_key",
    "huggingface_token",
    "replicate_token",
    # Cloud
    "digitalocean_pat",
    # Communication / SaaS
    "sendgrid_api_key",
    "twilio_account_sid",
    "discord_bot_token",
    "mailchimp_api_key",
    # DevOps / registries
    "gitlab_pat",
    "npm_token",
    "pypi_token",
    # E-commerce / payments
    "shopify_token",
    "square_api_key",
    "razorpay_live_key",
}


def test_every_detector_fires():
    findings = scan_text("config.py", SAMPLE)
    found_ids = {f.rule_id for f in findings}
    missing = EXPECTED_RULE_IDS - found_ids
    assert not missing, f"detectors did not fire for: {missing}"


def test_line_numbers_are_reported():
    findings = scan_text("config.py", SAMPLE)
    for f in findings:
        assert f.line_number >= 1


def test_secrets_are_redacted_not_leaked():
    raw_values = [
        "AKIA1234567890ABCDEF",
        "ghp_012345678901234567890123456789abcdef",
        "sk_live_0123456789abcdefABCDEFgh",
    ]
    findings = scan_text("config.py", SAMPLE)
    for f in findings:
        for raw in raw_values:
            assert raw not in f.redacted_line, f"leaked secret in line: {f.redacted_line}"
            assert raw not in f.match_preview, f"leaked secret in preview: {f.match_preview}"


def test_redaction_keeps_first6_last4():
    out = redact_secret("AKIA1234567890ABCDEF")  # 20 chars
    assert out.startswith("AKIA12")
    assert out.endswith("CDEF")
    assert "*" in out
    short = redact_secret("abc")
    assert short == "***"


def test_committed_env_file_detected():
    findings = scan_text(".env", "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n")
    ids = {f.rule_id for f in findings}
    assert "committed_env_file" in ids
    assert "aws_access_key_id" in ids  # still scans the file's contents


def test_weak_rule_placeholders_are_suppressed():
    # Keyword-only rules (api_key/password) with dummy values are pure noise.
    src = '\n'.join([
        'api_key = "your_api_key_here"',
        'password = "changeme"',
        'pwd = os.getenv("DB_PASSWORD")',
    ])
    findings = scan_text("config.py", src)
    assert findings == [], f"should have suppressed, got: {[f.rule_id for f in findings]}"


def test_strong_prefix_example_is_classified_not_hidden():
    # The canonical AWS example key still has a strong prefix — surface it, but
    # as a low-confidence Example/Template rather than a critical leak.
    findings = scan_text("config.py", 'aws = "AKIAIOSFODNN7EXAMPLE"')
    aws = [f for f in findings if f.rule_id == "aws_access_key_id"]
    assert len(aws) == 1
    assert aws[0].category == "Example / Template"
    assert aws[0].severity == "LOW"
    assert aws[0].confidence <= 20


def test_severity_assignments():
    findings = scan_text("config.py", SAMPLE)
    by_id = {f.rule_id: f.severity for f in findings}
    assert by_id["aws_access_key_id"] == "CRITICAL"
    assert by_id["stripe_secret_key"] == "CRITICAL"
    assert by_id["private_key"] == "CRITICAL"
    assert by_id["google_api_key"] == "HIGH"
    assert by_id["generic_api_key"] == "MEDIUM"
    assert by_id["stripe_publishable_key"] == "MEDIUM"


def test_parse_target_variants():
    assert parse_target("owner/repo") == ("owner", "repo")
    assert parse_target("https://github.com/owner/repo") == ("owner", "repo")
    assert parse_target("https://github.com/owner/repo.git") == ("owner", "repo")
    assert parse_target("github.com/owner/repo/") == ("owner", "repo")


# ----------------------------------------------------- multi-signal scoring

def test_templated_connection_string_is_low_confidence():
    src = 'URL="postgresql://${USER}:${ENC_PW}@${HOST}/postgres"'
    db = [f for f in scan_text("deploy.sh", src) if f.rule_id == "db_connection_string"]
    assert len(db) == 1, "template should still be surfaced, not suppressed"
    assert db[0].severity == "LOW"
    assert db[0].category == "Example / Template"
    assert db[0].confidence <= 20
    assert "${ENC_PW}" in db[0].match_preview  # literal shown (nothing to redact)


def test_hardcoded_connection_string_is_high_impact():
    src = 'URL="postgresql://admin:hunter2pw@db.internal/postgres"'
    db = [f for f in scan_text("config.py", src) if f.rule_id == "db_connection_string"]
    assert len(db) == 1
    assert db[0].severity == "HIGH"
    assert db[0].category in ("Likely Secret", "Potential Secret")
    assert "hunter2pw" not in db[0].match_preview  # real password redacted


def test_literal_password_with_variable_host_stays_high():
    # Only the host is a variable; the password is a real literal -> still HIGH.
    src = 'URL="postgresql://admin:hunter2pw@${HOST}/postgres"'
    db = [f for f in scan_text("config.py", src) if f.rule_id == "db_connection_string"]
    assert len(db) == 1
    assert db[0].severity == "HIGH"
    assert db[0].confidence >= 45


def test_templated_password_assignment_is_low():
    pw = [f for f in scan_text("settings.py", 'password = "${DB_PASSWORD}"')
          if f.rule_id == "hardcoded_password"]
    assert len(pw) == 1
    assert pw[0].severity == "LOW"
    assert pw[0].category == "Example / Template"


def test_strong_key_is_high_confidence_likely_secret():
    findings = scan_text("src/config.py", SAMPLE)
    aws = next(f for f in findings if f.rule_id == "aws_access_key_id")
    assert aws.confidence >= 80
    assert aws.category == "Likely Secret"
    assert any("format validation" in s for s in aws.signals)


def test_test_path_keeps_severity_but_lowers_confidence():
    # A real-format AWS key inside tests/ is still CRITICAL *if* real, but the
    # path context lowers confidence and re-categorises it as a Test Credential.
    src = 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'
    f = scan_text("tests/fixtures/aws_config.py", src)[0]
    assert f.severity == "CRITICAL"      # impact unchanged
    assert f.category == "Test Credential"
    assert f.confidence <= 40
    assert any("test/fixtures" in s for s in f.signals)


def test_example_file_path_lowers_confidence():
    f = scan_text("config.example", 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"')[0]
    assert f.category == "Documentation Sample"
    assert f.confidence <= 30


def test_dummy_variable_name_lowers_confidence():
    # High-entropy value but a test-y variable name -> reduced confidence.
    src = 'test_api_key = "Hq8sLm2Zx4Vn9Tb6Wc1Rd7Yf3Gk5Jp0Qe8Au"'
    findings = scan_text("app/service.py", src)
    gen = [f for f in findings if f.rule_id == "generic_api_key"]
    assert len(gen) == 1
    assert gen[0].category == "Test Credential"
    assert gen[0].confidence <= 45


def test_masked_keys_are_still_detected():
    # Developers sometimes replace chars with * thinking it hides the secret.
    # The prefix is still a definitive signal — we must surface these.
    cases = [
        ('config.py', 'gemini_api = "AIzaSy***********pu6A"', "google_api_key"),
        ('config.py', 'token = "AKIA****EXAMPLE"', "aws_access_key_id"),
        ('config.py', 'key = "sk_live_****abc"', "stripe_secret_key"),
        ('config.py', 'pat = "ghp_****1234567890abcdef"', "github_pat"),
        ('config.py', 'key = "sk-ant-api03-abc*****xyz"', "anthropic_api_key"),
        ('config.py', 'key = "glpat-abc***xyz1234"', "gitlab_pat"),
    ]
    for path, src, expected_id in cases:
        findings = scan_text(path, src)
        ids = {f.rule_id for f in findings}
        assert expected_id in ids, f"masked key not detected for rule {expected_id!r} in: {src!r}"


def test_entropy_signal_present_on_real_keys():
    findings = scan_text("src/config.py", SAMPLE)
    gh = next(f for f in findings if f.rule_id == "github_pat")
    assert gh.confidence >= 80
    assert gh.confidence_label == "High"
