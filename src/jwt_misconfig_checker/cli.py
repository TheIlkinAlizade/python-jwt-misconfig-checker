from pathlib import Path

import typer

from jwt_misconfig_checker import __version__
from jwt_misconfig_checker.checks.weak_secret import WeakSecretCheck, read_wordlist
from jwt_misconfig_checker.errors import TokenParseError
from jwt_misconfig_checker.models import Check, CheckContext
from jwt_misconfig_checker.parser import parse_token
from jwt_misconfig_checker.registry import DEFAULT_CHECKS
from jwt_misconfig_checker.runner import run_checks

DISCLAIMER = (
    "Use only on tokens and systems you own or are authorized to test. "
    "This tool performs offline static analysis and makes no network requests."
)
EXIT_INPUT_ERROR = 2

app = typer.Typer(add_completion=False, no_args_is_help=True)


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


@app.command(help=f"Analyze a JWT for security misconfigurations.\n\n{DISCLAIMER}")
def analyze(
    token: str = typer.Argument(..., help="The JWT to analyze."),
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
    try:
        parsed = parse_token(token)
    except TokenParseError as error:
        raise fail(str(error)) from error
    findings = run_checks(parsed, CheckContext(), checks)
    if not findings:
        typer.echo("No findings.")
    for finding in findings:
        typer.echo(
            f"{finding.severity.name} {finding.check_id} {finding.message} [{finding.location}]"
        )
