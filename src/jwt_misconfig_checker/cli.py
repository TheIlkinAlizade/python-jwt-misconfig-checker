import typer

from jwt_misconfig_checker import __version__

DISCLAIMER = (
    "Use only on tokens and systems you own or are authorized to test. "
    "This tool performs offline static analysis and makes no network requests."
)

app = typer.Typer(
    help=f"Analyze a JWT for security misconfigurations.\n\n{DISCLAIMER}",
    add_completion=False,
    no_args_is_help=True,
)


def show_version(value: bool) -> None:
    if value:
        typer.echo(f"jwt-misconfig-check {__version__}")
        raise typer.Exit()


@app.command()
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
    typer.echo("Analysis is not implemented yet.")