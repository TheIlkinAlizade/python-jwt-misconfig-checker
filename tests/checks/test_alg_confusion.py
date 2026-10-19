import pytest

from jwt_misconfig_checker.checks.alg_confusion import AlgorithmConfusionCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = AlgorithmConfusionCheck()


def severities(header: dict[str, object]) -> list[Severity]:
    return [finding.severity for finding in run_check(CHECK, header)]


@pytest.mark.parametrize("algorithm", ["RS256", "RS512", "PS384", "ES256", "ES512", "EdDSA"])
def test_asymmetric_algorithms_get_an_info_note(algorithm: str) -> None:
    assert severities({"alg": algorithm}) == [Severity.INFO]


@pytest.mark.parametrize("algorithm", ["HS256", "HS512", "none", "RSX", "RS", "ES256K", None, 5])
def test_other_algorithms_are_not_assessed(algorithm: object) -> None:
    assert severities({"alg": algorithm}) == []


@pytest.mark.parametrize("name", ["kid", "jku", "x5u"])
def test_key_reference_raises_to_low(name: str) -> None:
    assert severities({"alg": "RS256", name: "value"}) == [Severity.LOW]


@pytest.mark.parametrize("name", ["jwk", "x5c"])
def test_embedded_key_raises_to_medium(name: str) -> None:
    assert severities({"alg": "RS256", name: {}}) == [Severity.MEDIUM]


def test_evidence_lists_the_signals() -> None:
    findings = run_check(CHECK, {"alg": "RS256", "kid": "k1", "jwk": {}})
    assert findings[0].evidence == "alg=RS256, kid, jwk"
    assert findings[0].location == "header.alg"
