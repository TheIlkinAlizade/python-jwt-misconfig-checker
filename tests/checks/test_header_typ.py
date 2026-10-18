import pytest

from jwt_misconfig_checker.checks.header_typ import HeaderTypCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = HeaderTypCheck()


@pytest.mark.parametrize("media_type", ["JWT", "jwt", "at+jwt", "application/jwt", "JOSE"])
def test_accepts_expected_types(media_type: str) -> None:
    assert run_check(CHECK, {"alg": "HS256", "typ": media_type}) == []


def test_ignores_missing_typ() -> None:
    assert run_check(CHECK, {"alg": "HS256"}) == []


def test_flags_unexpected_type_as_info() -> None:
    findings = run_check(CHECK, {"alg": "HS256", "typ": "secevent+jwt"})
    assert [finding.severity for finding in findings] == [Severity.INFO]
    assert findings[0].location == "header.typ"


@pytest.mark.parametrize("media_type", [None, 1, ["JWT"], {"a": 1}])
def test_flags_non_string_type_as_low(media_type: object) -> None:
    findings = run_check(CHECK, {"alg": "HS256", "typ": media_type})
    assert [finding.severity for finding in findings] == [Severity.LOW]
