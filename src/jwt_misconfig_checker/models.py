from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParsedToken:
    header: dict[str, Any]
    payload: dict[str, Any]
    signing_input: bytes
    signature: bytes