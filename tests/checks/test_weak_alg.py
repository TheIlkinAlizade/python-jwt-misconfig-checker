import pytest

from jwt_misconfig_checker.checks.weak_alg import WeakAlgorithmCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = WeakAlgorithmCheck()

IGNORED_HEADERS: list[dict[str, object]] = [
    {},
    {"alg": "none"},
    {"alg": "NONE"},
    {"alg": 5},
    {"alg": None},
]


@pytest.mark.parametrize(
    "algorithm",
    ["HS256", "HS384", "HS512", "RS256", "ES256", "ES256K", "PS512", "EdDSA"],
)
def test_accepts_registered_algorithms(algorithm: str) -> None:
    assert run_check(CHECK, {"alg": algorithm}) == []


@pytest.mark.parametrize("algorithm", ["HS1", "rs1", "MD5", "HmacSha1"])
def test_flags_weak_digests_as_high(algorithm: str) -> None:
    findings = run_check(CHECK, {"alg": algorithm})
    assert [finding.severity for finding in findings] == [Severity.HIGH]


@pytest.mark.parametrize("algorithm", ["RSA1_5", "dir", "A128KW", "ECDH-ES"])
def test_flags_key_management_algorithms_as_medium(algorithm: str) -> None:
    findings = run_check(CHECK, {"alg": algorithm})
    assert [finding.severity for finding in findings] == [Severity.MEDIUM]


@pytest.mark.parametrize("algorithm", ["hs256", "Rs256", "EDDSA", "eddsa"])
def test_flags_wrong_capitalization_as_medium(algorithm: str) -> None:
    findings = run_check(CHECK, {"alg": algorithm})
    assert [finding.severity for finding in findings] == [Severity.MEDIUM]


@pytest.mark.parametrize("algorithm", ["HS999", "", "RS256 ", "custom"])
def test_flags_unrecognized_values_as_low(algorithm: str) -> None:
    findings = run_check(CHECK, {"alg": algorithm})
    assert [finding.severity for finding in findings] == [Severity.LOW]


@pytest.mark.parametrize("header", IGNORED_HEADERS)
def test_leaves_none_missing_and_non_string_to_the_none_check(header: dict[str, object]) -> None:
    assert run_check(CHECK, header) == []


def test_evidence_is_escaped_and_bounded() -> None:
    findings = run_check(CHECK, {"alg": "\x1b[2J" + "A" * 500})
    assert "\x1b" not in findings[0].evidence
    assert len(findings[0].evidence) <= 64
