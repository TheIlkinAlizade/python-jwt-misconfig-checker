from datetime import UTC, datetime

from jwt_misconfig_checker.models import CheckContext, Severity
from jwt_misconfig_checker.parser import parse_token
from jwt_misconfig_checker.runner import run_checks
from tests.tokens import build_token

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONTEXT = CheckContext(now=lambda: NOW)
GOOD_PAYLOAD = {
    "sub": "42",
    "iss": "https://issuer.example.com",
    "aud": "my-api",
    "iat": int(NOW.timestamp()),
    "exp": int(NOW.timestamp()) + 900,
}


def test_runner_reports_findings_for_bad_token() -> None:
    token = parse_token(build_token({"alg": "none"}, GOOD_PAYLOAD, b""))
    findings = run_checks(token, CONTEXT)
    assert [finding.check_id for finding in findings] == ["JWT-ALG-001"]
    assert findings[0].severity is Severity.CRITICAL


def test_runner_reports_nothing_for_clean_token() -> None:
    token = parse_token(build_token({"alg": "RS256", "typ": "JWT"}, GOOD_PAYLOAD))
    assert run_checks(token, CONTEXT) == []


def test_runner_orders_findings_by_severity() -> None:
    token = parse_token(build_token({"alg": "hs256", "typ": "x"}, GOOD_PAYLOAD))
    findings = run_checks(token, CONTEXT)
    assert [finding.check_id for finding in findings] == ["JWT-ALG-002", "JWT-HDR-001"]
    assert findings[0].severity > findings[1].severity
