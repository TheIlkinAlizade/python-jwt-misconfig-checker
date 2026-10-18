from typing import Any

from jwt_misconfig_checker.models import Check, CheckContext, Finding
from jwt_misconfig_checker.parser import parse_token
from tests.tokens import build_token

DEFAULT_PAYLOAD: dict[str, Any] = {"sub": "42"}


def run_check(
    check: Check,
    header: dict[str, Any],
    payload: dict[str, Any] | None = None,
    signature: bytes = b"signature",
    context: CheckContext | None = None,
) -> list[Finding]:
    raw = build_token(header, DEFAULT_PAYLOAD if payload is None else payload, signature)
    return check.run(parse_token(raw), context or CheckContext())
