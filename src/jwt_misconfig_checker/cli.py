import typer

from jwt_misconfig_checker import __version__
from jwt_misconfig_checker.errors import TokenParseError
from jwt_misconfig_checker.models import CheckContext
from jwt_misconfig_checker.parser import parse_token
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


@app.command(help=f"Analyze a JWT for security misconfigurations.\n\n{DISCLAIMER}")
def analyze(
    token: str = typer.Argument(..., help="The JWT to analyze."),
    version: bool = typer.Option(
        False,
        "--version",
        callback=show_version,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    try:
        parsed = parse_token(token)
    except TokenParseError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=EXIT_INPUT_ERROR) from error
    findings = run_checks(parsed, CheckContext())
    if not findings:
        typer.echo("No findings.")
    for finding in findings:
        typer.echo(
            f"{finding.severity.name} {finding.check_id} "
            f"{finding.message} [{finding.location}]"
        )