from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console

from jwt_misconfig_checker import __version__
from jwt_misconfig_checker.checks.weak_secret import WeakSecretCheck, read_wordlist
from jwt_misconfig_checker.errors import InputError, TokenParseError
from jwt_misconfig_checker.input_source import read_token
from jwt_misconfig_checker.models import Check, CheckContext, Finding, Severity
from jwt_misconfig_checker.parser import parse_token
from jwt_misconfig_checker.redaction import redact_token
from jwt_misconfig_checker.registry import DEFAULT_CHECKS
from jwt_misconfig_checker.reporting.human import render_human
from jwt_misconfig_checker.reporting.json_report import render_json
from jwt_misconfig_checker.runner import run_checks

DISCLAIMER = (
    "Use only on tokens and systems you own or are authorized to test. "
    "This tool performs offline static analysis and makes no network requests."
)
EXIT_FINDINGS = 1
EXIT_INPUT_ERROR = 2

app = typer.Typer(add_completion=False, no_args_is_help=True)


class OutputFormat(StrEnum):
    human = "human"
    json = "json"


class FailOn(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


def show_version(value: bool) -> None:
    if value:
        typer.echo(f"jwt-misconfig-check {__version__}")
        raise typer.Exit()


def fail(message: str) -> typer.Exit:
    typer.echo(f"Error: {message}", err=True)
    return typer.Exit(code=EXIT_INPUT_ERROR)


def selected_checks(wordlist: Path | None, confirmed: bool) -> tuple[Check, ...]:
    if wordlist is None:
        return DEFAULT_CHECKS
    if not confirmed:
        raise fail("--wordlist requires --i-own-this-token to confirm you own this token")
    typer.echo("Testing the HMAC secret offline against your wordlist.", err=True)
    return (*DEFAULT_CHECKS, WeakSecretCheck(read_wordlist(wordlist)))


def load_token(source: str | None, file: Path | None) -> str:
    try:
        return read_token(source, file).strip()
    except InputError as error:
        raise fail(str(error)) from error


def emit(
    findings: list[Finding],
    checks: tuple[Check, ...],
    token_display: str,
    output_format: OutputFormat,
) -> None:
    if output_format is OutputFormat.json:
        typer.echo(render_json(findings, checks, token_display))
    else:
        render_human(findings, checks, token_display, Console(highlight=False))


@app.command(
    help=(
        "Analyze a JWT for security misconfigurations. Pass the token as an argument, "
        f"'-' to read it from stdin, or use --file.\n\n{DISCLAIMER}"
    )
)
def analyze(
    token: str | None = typer.Argument(None, help="The JWT, or '-' to read it from stdin."),
    file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Read the token from a file.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.human, "--format", help="Report format."
    ),
    fail_on: FailOn = typer.Option(
        FailOn.high, "--fail-on", help="Exit with code 1 if a finding is at or above this severity."
    ),
    show_token: bool = typer.Option(
        False, "--show-token", help="Include the full token in the report. Redacted by default."
    ),
    wordlist: Path | None = typer.Option(
        None,
        "--wordlist",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Optional wordlist for an offline weak HMAC secret check.",
    ),
    confirmed: bool = typer.Option(
        False,
        "--i-own-this-token",
        help="Confirm you own this token or are authorized to test it. Required with --wordlist.",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        callback=show_version,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    checks = selected_checks(wordlist, confirmed)
    raw = load_token(token, file)
    try:
        parsed = parse_token(raw)
    except TokenParseError as error:
        raise fail(str(error)) from error
    findings = run_checks(parsed, CheckContext(), checks)
    emit(findings, checks, raw if show_token else redact_token(raw), output_format)
    threshold = Severity[fail_on.value.upper()]
    if any(finding.severity >= threshold for finding in findings):
        raise typer.Exit(code=EXIT_FINDINGS)
