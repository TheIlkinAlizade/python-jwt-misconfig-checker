import contextlib
import string
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from jwt_misconfig_checker.errors import TokenParseError
from jwt_misconfig_checker.parser import parse_token
from tests.tokens import build_token, encode_segment

TOKEN_ALPHABET = string.ascii_letters + string.digits + "-_.="

json_values = st.none() | st.booleans() | st.integers(-(2**53), 2**53) | st.text()
json_objects = st.dictionaries(st.text(), json_values, max_size=10)
random_segment = st.binary(max_size=200).map(encode_segment)


@given(st.text())
def test_arbitrary_text_never_crashes(raw: str) -> None:
    with contextlib.suppress(TokenParseError):
        parse_token(raw)


@given(st.text(alphabet=TOKEN_ALPHABET, max_size=300))
def test_token_shaped_text_never_crashes(raw: str) -> None:
    with contextlib.suppress(TokenParseError):
        parse_token(raw)


@given(random_segment, random_segment, random_segment)
def test_random_decoded_bytes_never_crash(header: str, payload: str, signature: str) -> None:
    with contextlib.suppress(TokenParseError):
        parse_token(f"{header}.{payload}.{signature}")


@given(json_objects, json_objects, st.binary(max_size=100))
def test_valid_tokens_round_trip(
    header: dict[str, Any], payload: dict[str, Any], signature: bytes
) -> None:
    parsed = parse_token(build_token(header, payload, signature))
    assert parsed.header == header
    assert parsed.payload == payload
    assert parsed.signature == signature
