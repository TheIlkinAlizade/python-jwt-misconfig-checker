import pytest

from jwt_misconfig_checker.checks.alg_none import AlgNoneCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = AlgNoneCheck()


@pytest.mark.parametrize("algorithm", ["none", "None", "NONE", "nOnE"])
def test_flags_none_in_any_capitalization(algorithm: str) -> None:
    findings = run_check(CHECK, {"alg": algorithm}, signature=b"")
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].location == "header.alg"


def test_flags_none_even_with_a_signature_present() -> None:
    findings = run_check(CHECK, {"alg": "none"}, signature=b"unexpected")
    assert findings[0].severity is Severity.CRITICAL


def test_flags_missing_alg() -> None:
    findings = run_check(CHECK, {"typ": "JWT"})
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


@pytest.mark.parametrize("algorithm", [None, 0, ["HS256"], {"a": 1}, True])
def test_flags_non_string_alg(algorithm: object) -> None:
    findings = run_check(CHECK, {"alg": algorithm})
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


@pytest.mark.parametrize("algorithm", ["HS256", "RS256", "ES256", "EdDSA"])
def test_accepts_real_algorithms(algorithm: str) -> None:
    assert run_check(CHECK, {"alg": algorithm}) == []

