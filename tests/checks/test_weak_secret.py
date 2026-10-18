import hmac
from pathlib import Path

import pytest

from jwt_misconfig_checker.checks.weak_secret import WeakSecretCheck, read_wordlist
from jwt_misconfig_checker.models import CheckContext, Severity
from jwt_misconfig_checker.parser import parse_token
from tests.tokens import build_token, encode_segment

DIGESTS = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
WORDLIST = [b"password", b"letmein", b"secret", b"admin"]


def signed_token(algorithm: str, secret: bytes) -> str:
    unsigned = build_token({"alg": algorithm, "typ": "JWT"}, {"sub": "42"})
    signing_input = unsigned.rsplit(".", 1)[0]
    signature = hmac.digest(secret, signing_input.encode("ascii"), DIGESTS[algorithm])
    return f"{signing_input}.{encode_segment(signature)}"


def run(raw: str, candidates: list[bytes]) -> list[tuple[str, Severity]]:
    findings = WeakSecretCheck(candidates).run(parse_token(raw), CheckContext())
    return [(finding.location, finding.severity) for finding in findings]


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_finds_a_weak_secret(algorithm: str) -> None:
    assert run(signed_token(algorithm, b"secret"), WORDLIST) == [("signature", Severity.CRITICAL)]


def test_strong_secret_is_not_found() -> None:
    token = signed_token("HS256", b"k9#Vq2!mZx8$Lp0wRt5&Yb3nUe7@Hd1c")
    assert run(token, WORDLIST) == []


def test_empty_secret_is_found() -> None:
    assert run(signed_token("HS256", b""), [b"", b"x"]) == [("signature", Severity.CRITICAL)]


@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "none", "hs256", "EdDSA"])
def test_non_hmac_algorithms_are_skipped(algorithm: str) -> None:
    raw = build_token({"alg": algorithm}, {"sub": "42"}, b"signature")
    assert run(raw, WORDLIST) == []


@pytest.mark.parametrize("algorithm", [None, 5, ["HS256"], {"a": 1}])
def test_odd_alg_values_do_not_crash(algorithm: object) -> None:
    raw = build_token({"alg": algorithm}, {"sub": "42"}, b"signature")
    assert run(raw, WORDLIST) == []


def test_empty_wordlist_finds_nothing() -> None:
    assert run(signed_token("HS256", b"secret"), []) == []


def test_evidence_never_contains_the_secret() -> None:
    parsed = parse_token(signed_token("HS256", b"hunter2"))
    findings = WeakSecretCheck([b"hunter2"]).run(parsed, CheckContext())
    assert "hunter2" not in findings[0].evidence
    assert "7 characters" in findings[0].evidence


def test_wordlist_reader_strips_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "words.txt"
    path.write_bytes(b"one\r\ntwo\nthree")
    assert list(read_wordlist(path)) == [b"one", b"two", b"three"]
