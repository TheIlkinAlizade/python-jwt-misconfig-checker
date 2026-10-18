import pytest

from jwt_misconfig_checker.checks.sensitive_data import SensitiveDataCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = SensitiveDataCheck()
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a" * 36
VALID_CARD = "4111 1111 1111 1111"
INVALID_CARD = "4111 1111 1111 1112"


def findings_for(payload: dict[str, object]) -> list[tuple[str, Severity]]:
    return [
        (finding.location, finding.severity)
        for finding in run_check(CHECK, {"alg": "RS256"}, payload)
    ]


def test_minimal_payload_is_clean() -> None:
    assert findings_for({"sub": "42", "scope": "read write", "role": "admin"}) == []


@pytest.mark.parametrize("name", ["password", "user_password", "userPassword", "pwd", "passwd"])
def test_password_names_are_high(name: str) -> None:
    assert findings_for({name: "hunter2"}) == [(f"payload.{name}", Severity.HIGH)]


@pytest.mark.parametrize("name", ["secret", "api_key", "apiKey", "client_secret", "private_key"])
def test_secret_names_are_medium(name: str) -> None:
    assert findings_for({name: "abc"}) == [(f"payload.{name}", Severity.MEDIUM)]


@pytest.mark.parametrize("name", ["keyboard", "secretary", "compass"])
def test_lookalike_names_are_not_flagged(name: str) -> None:
    assert findings_for({name: "x"}) == []


def test_empty_sensitive_fields_are_ignored() -> None:
    assert findings_for({"password": "", "secret": None, "api_key": False}) == []


@pytest.mark.parametrize(
    ("value", "severity"),
    [
        (AWS_KEY, Severity.HIGH),
        (GITHUB_TOKEN, Severity.HIGH),
        ("-----BEGIN RSA PRIVATE KEY-----", Severity.HIGH),
        ("sk_live_" + "a" * 20, Severity.HIGH),
        ("alice@example.com", Severity.LOW),
        (VALID_CARD, Severity.MEDIUM),
    ],
)
def test_value_shapes_are_detected(value: str, severity: Severity) -> None:
    assert findings_for({"data": value}) == [("payload.data", severity)]


def test_invalid_card_number_is_not_flagged() -> None:
    assert findings_for({"data": INVALID_CARD}) == []


def test_embedded_jwt_is_medium() -> None:
    inner = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
    assert findings_for({"data": inner}) == [("payload.data", Severity.MEDIUM)]


def test_nested_fields_report_their_path() -> None:
    assert findings_for({"user": {"profile": {"password": "x"}}}) == [
        ("payload.user.profile.password", Severity.HIGH)
    ]


def test_list_items_are_scanned() -> None:
    assert findings_for({"contacts": ["bob@example.com"]}) == [
        ("payload.contacts[0]", Severity.LOW)
    ]


def test_deep_nesting_is_bounded() -> None:
    payload: dict[str, object] = {"password": "x"}
    for _ in range(50):
        payload = {"a": payload}
    assert findings_for(payload) == []


def test_evidence_never_contains_the_secret() -> None:
    findings = run_check(CHECK, {"alg": "RS256"}, {"password": "hunter2", "data": AWS_KEY})
    assert all("hunter2" not in finding.evidence for finding in findings)
    assert all(AWS_KEY not in finding.evidence for finding in findings)


def test_email_evidence_is_masked() -> None:
    findings = run_check(CHECK, {"alg": "RS256"}, {"contact": "alice@example.com"})
    assert findings[0].evidence == "a***@example.com"
