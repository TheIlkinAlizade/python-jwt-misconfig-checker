import sys
from pathlib import Path

from jwt_misconfig_checker.errors import InputError
from jwt_misconfig_checker.parser import MAX_TOKEN_LENGTH

STDIN_MARKER = "-"
READ_LIMIT = MAX_TOKEN_LENGTH + 1024


def read_token(argument: str | None, file: Path | None) -> str:
    if (argument is None) == (file is None):
        raise InputError("provide exactly one of: a token, '-' for stdin, or --file")
    try:
        if file is not None:
            return read_file(file)
        if argument == STDIN_MARKER:
            return sys.stdin.read(READ_LIMIT)
    except (OSError, UnicodeDecodeError) as error:
        raise InputError("the input could not be read as text") from error
    return argument or ""


def read_file(path: Path) -> str:
    with path.open(encoding="utf-8") as handle:
        return handle.read(READ_LIMIT)
