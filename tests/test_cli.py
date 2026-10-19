import json
import time
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from jwt_misconfig_checker.cli import app
from tests.checks.test_weak_secret import signed_token
from tests.tokens import build_token

runner = CliRunner()


def fresh_payload(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    payload = {
        "sub": "42",
        "iss": "https://issuer.example.com",
        "aud": "my-api",
        "iat": now,
        "exp": now + 900,
    }
    return {**payload, **overrides}


CLEAN_TOKEN = build_token({"alg": "HS256", "typ": "JWT"}, fresh_payload())
NONE_TOKEN = build_token({"alg": "none", "typ": "JWT"}, fresh_payload(), b"")
NO_EXPIRY_TOKEN = build_token(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "42", "iss": "https://issuer.example.com", "aud": "my-api"},
)


def wordlist_file(tmp_path: Path) -> Path:
    path = tmp_path / "words.txt"
    path.write_text("password\nsecret\n", encoding="utf-8")
    return path


def test_wordlist_requires_confirmation(tmp_path: Path) -> None:
    token = signed_token("HS256", b"secret")
    result = runner.invoke(app, [token, "--wordlist", str(wordlist_file(tmp_path))])
    assert result.exit_code == 2
    assert "--i-own-this-token" in result.output
    assert "JWT-SEC-001" not in result.output


def test_confirmed_wordlist_reports_the_weak_secret(tmp_path: Path) -> None:
    token = signed_token("HS256", b"secret")
    args = [token, "--wordlist", str(wordlist_file(tmp_path)), "--i-own-this-token"]
    result = runner.invoke(app, args)
    assert "CRITICAL JWT-SEC-001" in result.output
    assert result.exit_code == 1


def test_default_run_never_tests_secrets() -> None:
    result = runner.invoke(app, [signed_token("HS256", b"secret")])
    assert "JWT-SEC-001" not in result.output


def test_malformed_token_exits_with_input_error() -> None:
    assert runner.invoke(app, ["abc.def.ghi"]).exit_code == 2


def test_clean_token_exits_zero() -> None:
    result = runner.invoke(app, [CLEAN_TOKEN])
    assert result.exit_code == 0
    assert "No findings." in result.output


def test_critical_finding_exits_one_by_default() -> None:
    result = runner.invoke(app, [NONE_TOKEN])
    assert result.exit_code == 1
    assert "CRITICAL JWT-ALG-001" in result.output


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [("info", 1), ("high", 1), ("critical", 0)],
)
def test_fail_on_threshold(threshold: str, expected: int) -> None:
    result = runner.invoke(app, [NO_EXPIRY_TOKEN, "--fail-on", threshold])
    assert result.exit_code == expected


def test_invalid_fail_on_value_is_a_usage_error() -> None:
    assert runner.invoke(app, [CLEAN_TOKEN, "--fail-on", "severe"]).exit_code == 2


def test_token_is_redacted_by_default() -> None:
    result = runner.invoke(app, [CLEAN_TOKEN])
    assert CLEAN_TOKEN not in result.output
    assert CLEAN_TOKEN[:8] in result.output


def test_show_token_prints_the_full_token() -> None:
    result = runner.invoke(app, [CLEAN_TOKEN, "--show-token"])
    assert CLEAN_TOKEN in result.output


def test_reads_token_from_stdin() -> None:
    result = runner.invoke(app, ["-"], input=NONE_TOKEN + "\n")
    assert "JWT-ALG-001" in result.output


def test_reads_token_from_file(tmp_path: Path) -> None:
    path = tmp_path / "token.txt"
    path.write_text(NONE_TOKEN + "\n", encoding="utf-8")
    result = runner.invoke(app, ["--file", str(path)])
    assert "JWT-ALG-001" in result.output


def test_token_and_file_together_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "token.txt"
    path.write_text(CLEAN_TOKEN, encoding="utf-8")
    result = runner.invoke(app, [CLEAN_TOKEN, "--file", str(path)])
    assert result.exit_code == 2


def test_json_output_has_a_stable_shape() -> None:
    result = runner.invoke(app, [NONE_TOKEN, "--format", "json"])
    report = json.loads(result.stdout)
    assert report["tool"] == "jwt-misconfig-check"
    assert report["summary"]["by_severity"]["CRITICAL"] == 1
    finding = report["findings"][0]
    assert finding["id"] == "JWT-ALG-001"
    assert finding["remediation"]
    assert finding["references"]
    assert NONE_TOKEN not in result.stdout


def test_json_exit_code_matches_threshold() -> None:
    result = runner.invoke(app, [NONE_TOKEN, "--format", "json", "--fail-on", "critical"])
    assert result.exit_code == 1


def test_markup_in_token_values_is_printed_literally() -> None:
    token = build_token({"alg": "HS256", "kid": "[red]x';--"}, fresh_payload())
    result = runner.invoke(app, [token])
    assert "[red]" in result.output
