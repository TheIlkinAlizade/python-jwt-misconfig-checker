import base64
import json
from typing import Any


def encode_segment(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_json_segment(value: Any) -> str:
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return encode_segment(text.encode("utf-8"))


def build_token(
    header: dict[str, Any],
    payload: dict[str, Any],
    signature: bytes = b"signature",
) -> str:
    return (
        f"{encode_json_segment(header)}."
        f"{encode_json_segment(payload)}."
        f"{encode_segment(signature)}"
    )