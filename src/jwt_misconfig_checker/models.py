from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, Protocol


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class ParsedToken:
    header: dict[str, Any]
    payload: dict[str, Any]
    signing_input: bytes
    signature: bytes


@dataclass(frozen=True)
class CheckContext:
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: Severity
    message: str
    location: str
    evidence: str


class Check(Protocol):
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...]

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]: ...
