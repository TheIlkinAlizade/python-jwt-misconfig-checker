import base64
import binascii
import json
import re
from typing import Any, NoReturn

from jwt_misconfig_checker.errors import TokenParseError
from jwt_misconfig_checker.models import ParsedToken

MAX_JSON_DEPTH = 32
MAX_TOKEN_LENGTH = 32_768
BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]*")


def encode_segment(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def split_token(token: str) -> tuple[str, str, str]:
    cleaned = token.strip()
    if len(cleaned) > MAX_TOKEN_LENGTH:
        raise TokenParseError(f"token exceeds the maximum length of {MAX_TOKEN_LENGTH} characters")
    segments = cleaned.split(".")
    if len(segments) == 5:
        raise TokenParseError(
            "token has five segments and looks like an encrypted JWT (JWE); "
            "only signed JWTs (JWS) are supported"
        )
    if len(segments) != 3:
        raise TokenParseError(f"token must have exactly 3 segments, found {len(segments)}")
    return segments[0], segments[1], segments[2]


def decode_segment(segment: str, name: str) -> bytes:
    if not BASE64URL_PATTERN.fullmatch(segment):
        raise TokenParseError(f"{name} contains characters outside the base64url alphabet")
    if len(segment) % 4 == 1:
        raise TokenParseError(f"{name} has an impossible base64url length")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as error:
        raise TokenParseError(f"{name} is not valid base64url") from error
    if encode_segment(decoded) != segment:
        raise TokenParseError(f"{name} is not canonical base64url")
    return decoded


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise TokenParseError("has duplicate keys")
    return dict(pairs)


def reject_constant(value: str) -> NoReturn:
    raise TokenParseError("contains a non-standard number constant")


def exceeds_depth(value: Any, limit: int) -> bool:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict | list):
            if depth > limit:
                return True
            children = current.values() if isinstance(current, dict) else current
            stack.extend((child, depth + 1) for child in children)
    return False


def parse_json_object(data: bytes, name: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TokenParseError(f"{name} is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except TokenParseError as error:
        raise TokenParseError(f"{name} {error}") from error
    except (json.JSONDecodeError, RecursionError) as error:
        raise TokenParseError(f"{name} is not valid JSON") from error
    if not isinstance(value, dict):
        raise TokenParseError(f"{name} must be a JSON object")
    if exceeds_depth(value, MAX_JSON_DEPTH):
        raise TokenParseError(f"{name} is nested too deeply")
    return value


def parse_token(token: str) -> ParsedToken:
    header_segment, payload_segment, signature_segment = split_token(token)
    header = parse_json_object(decode_segment(header_segment, "header"), "header")
    payload = parse_json_object(decode_segment(payload_segment, "payload"), "payload")
    signature = decode_segment(signature_segment, "signature")
    return ParsedToken(
        header=header,
        payload=payload,
        signing_input=f"{header_segment}.{payload_segment}".encode("ascii"),
        signature=signature,
    )
