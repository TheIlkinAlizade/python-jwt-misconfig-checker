import pytest

from jwt_misconfig_checker.checks.identity_claims import IdentityClaimsCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = IdentityClaimsCheck()


def findings_for(payload: dict[str, object]) -> list[tuple[str, Severity]]:
    return [
        (finding.location, finding.severity)
        for finding in run_check(CHECK, {"alg": "RS256"}, payload)
    ]


def test_valid_claims_are_clean() -> None:
    assert findings_for({"iss": "https://i.example.com", "aud": "api"}) == []


def test_audience_list_is_clean() -> None:
    assert findings_for({"iss": "https://i.example.com", "aud": ["a", "b"]}) == []


def test_missing_both_reports_two_findings() -> None:
    assert findings_for({}) == [
        ("payload.iss", Severity.MEDIUM),
        ("payload.aud", Severity.MEDIUM),
    ]


def test_missing_audience_only() -> None:
    assert findings_for({"iss": "x"}) == [("payload.aud", Severity.MEDIUM)]


@pytest.mark.parametrize("value", ["", None, 5, [], [""], [1], {"a": 1}, True])
def test_malformed_audience_is_low(value: object) -> None:
    assert findings_for({"iss": "x", "aud": value}) == [("payload.aud", Severity.LOW)]


@pytest.mark.parametrize("value", ["", None, 5, ["x"], {"a": 1}])
def test_malformed_issuer_is_low(value: object) -> None:
    assert findings_for({"iss": value, "aud": "api"}) == [("payload.iss", Severity.LOW)]