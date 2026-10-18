import pytest

from jwt_misconfig_checker.checks.header_params import HeaderParametersCheck
from jwt_misconfig_checker.models import Severity
from tests.checks.helpers import run_check

CHECK = HeaderParametersCheck()


def severities(header: dict[str, object]) -> list[Severity]:
    return [finding.severity for finding in run_check(CHECK, header)]


def test_clean_header_has_no_findings() -> None:
    assert severities({"alg": "RS256", "typ": "JWT", "kid": "key-1"}) == []


@pytest.mark.parametrize("name", ["jwk", "x5c"])
def test_embedded_keys_are_high(name: str) -> None:
    findings = run_check(CHECK, {"alg": "RS256", name: {"kty": "RSA"}})
    assert [finding.severity for finding in findings] == [Severity.HIGH]
    assert findings[0].location == f"header.{name}"


@pytest.mark.parametrize("name", ["jku", "x5u"])
def test_https_public_url_is_medium(name: str) -> None:
    assert severities({"alg": "RS256", name: "https://keys.example.com/jwks.json"}) == [
        Severity.MEDIUM
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://keys.example.com/jwks.json",
        "https://localhost/jwks.json",
        "https://127.0.0.1/jwks.json",
        "https://10.0.0.5/jwks.json",
        "https://192.168.1.1/jwks.json",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/jwks.json",
        "https://service.internal/jwks.json",
        "https://user:pass@keys.example.com/jwks.json",
        "file:///etc/passwd",
        "ftp://keys.example.com/jwks.json",
        "//keys.example.com/jwks.json",
        "not a url",
        "",
    ],
)
def test_risky_urls_are_high(url: str) -> None:
    assert severities({"alg": "RS256", "jku": url}) == [Severity.HIGH]


@pytest.mark.parametrize("value", [None, 5, ["https://a.example"], {"a": 1}])
def test_non_string_urls_are_low(value: object) -> None:
    assert severities({"alg": "RS256", "x5u": value}) == [Severity.LOW]


def test_multiple_parameters_report_separately() -> None:
    findings = run_check(
        CHECK,
        {"alg": "RS256", "jwk": {}, "jku": "https://keys.example.com/jwks.json"},
    )
    assert sorted(finding.location for finding in findings) == ["header.jku", "header.jwk"]


def test_malformed_url_does_not_crash() -> None:
    assert severities({"alg": "RS256", "jku": "https://[invalid/jwks.json"}) == [Severity.HIGH]


def test_evidence_is_escaped_and_bounded() -> None:
    findings = run_check(CHECK, {"alg": "RS256", "jku": "\x1b[2J" + "a" * 500})
    assert "\x1b" not in findings[0].evidence
    assert len(findings[0].evidence) <= 64
