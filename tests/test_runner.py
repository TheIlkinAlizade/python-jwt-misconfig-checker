from jwt_misconfig_checker.models import CheckContext, Severity
from jwt_misconfig_checker.parser import parse_token
from jwt_misconfig_checker.runner import run_checks
from tests.tokens import build_token


def test_runner_reports_findings_for_bad_token() -> None:
    token = parse_token(build_token({"alg": "none"}, {"sub": "42"}, b""))
    findings = run_checks(token, CheckContext())
    assert [finding.check_id for finding in findings] == ["JWT-ALG-001"]
    assert findings[0].severity is Severity.CRITICAL


def test_runner_reports_nothing_for_clean_token() -> None:
    token = parse_token(build_token({"alg": "RS256"}, {"sub": "42"}))
    assert run_checks(token, CheckContext()) == []


def test_runner_orders_findings_by_severity() -> None:
    token = parse_token(build_token({"alg": "hs256", "typ": "x"}, {"sub": "42"}))
    findings = run_checks(token, CheckContext())
    assert [finding.check_id for finding in findings] == ["JWT-ALG-002", "JWT-HDR-001"]
    assert findings[0].severity > findings[1].severity