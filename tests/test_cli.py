from pathlib import Path

from typer.testing import CliRunner

from jwt_misconfig_checker.cli import app
from tests.checks.test_weak_secret import signed_token

runner = CliRunner()


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


def test_default_run_never_tests_secrets() -> None:
    result = runner.invoke(app, [signed_token("HS256", b"secret")])
    assert "JWT-SEC-001" not in result.output


def test_malformed_token_exits_with_input_error() -> None:
    assert runner.invoke(app, ["abc.def.ghi"]).exit_code == 2
