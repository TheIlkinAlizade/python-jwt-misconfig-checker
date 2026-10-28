import pytest

from jwt_misconfig_checker.errors import TokenParseError
from jwt_misconfig_checker.parser import MAX_TOKEN_LENGTH, parse_token
from tests.tokens import build_token, encode_json_segment, encode_segment

HEADER = encode_json_segment({"alg": "HS256", "typ": "JWT"})
PAYLOAD = encode_json_segment({"sub": "1234567890"})
SIGNATURE = encode_segment(b"signature")


def token_with_header(raw_header: bytes) -> str:
    return f"{encode_segment(raw_header)}.{PAYLOAD}.{SIGNATURE}"


def token_with_payload(raw_payload: bytes) -> str:
    return f"{HEADER}.{encode_segment(raw_payload)}.{SIGNATURE}"


MALFORMED_TOKENS = {
    "empty": "",
    "single segment": "abc",
    "two segments": f"{HEADER}.{PAYLOAD}",
    "four segments": f"{HEADER}.{PAYLOAD}.{SIGNATURE}.extra",
    "empty segments": "..",
    "padding character": f"{HEADER}=.{PAYLOAD}.{SIGNATURE}",
    "standard base64 alphabet": f"e30+.{PAYLOAD}.{SIGNATURE}",
    "impossible length": f"e.{PAYLOAD}.{SIGNATURE}",
    "non canonical encoding": f"e31.{PAYLOAD}.{SIGNATURE}",
    "inner whitespace": f"{HEADER} .{PAYLOAD}.{SIGNATURE}",
    "non ascii character": f"{HEADER}é.{PAYLOAD}.{SIGNATURE}",
    "header not utf8": token_with_header(b"\xff\xfe"),
    "header not json": token_with_header(b"not json"),
    "header is array": token_with_header(b"[]"),
    "header is string": token_with_header(b'"text"'),
    "header is null": token_with_header(b"null"),
    "header duplicate keys": token_with_header(b'{"alg":"HS256","alg":"none"}'),
    "header nan constant": token_with_header(b'{"n":NaN}'),
    "payload is number": token_with_payload(b"123"),
    "payload duplicate keys": token_with_payload(b'{"sub":"a","sub":"b"}'),
    "payload deeply nested": token_with_payload(b'{"a":' * 3000 + b"1" + b"}" * 3000),
    "token too long": "a" * (MAX_TOKEN_LENGTH + 1),
}


def test_parses_well_formed_token() -> None:
    raw = build_token({"alg": "HS256", "typ": "JWT"}, {"sub": "42"}, b"sig-bytes")
    parsed = parse_token(raw)
    assert parsed.header == {"alg": "HS256", "typ": "JWT"}
    assert parsed.payload == {"sub": "42"}
    assert parsed.signature == b"sig-bytes"
    assert parsed.signing_input == raw.rsplit(".", 1)[0].encode("ascii")


def test_ignores_surrounding_whitespace() -> None:
    raw = build_token({"alg": "HS256"}, {"sub": "42"})
    assert parse_token(f"  {raw}\n") == parse_token(raw)


def test_accepts_empty_signature_for_unsecured_tokens() -> None:
    parsed = parse_token(build_token({"alg": "none"}, {}, b""))
    assert parsed.signature == b""


def test_preserves_unicode_values() -> None:
    payload = {"name": "Zoë 日本語 🔐"}
    assert parse_token(build_token({"alg": "HS256"}, payload)).payload == payload


@pytest.mark.parametrize("raw", MALFORMED_TOKENS.values(), ids=MALFORMED_TOKENS.keys())
def test_rejects_malformed_tokens(raw: str) -> None:
    with pytest.raises(TokenParseError):
        parse_token(raw)


def test_reports_encrypted_tokens_specifically() -> None:
    with pytest.raises(TokenParseError, match="encrypted"):
        parse_token("a.b.c.d.e")


def test_error_messages_do_not_echo_the_token() -> None:
    raw = token_with_header(b"not json")
    with pytest.raises(TokenParseError) as excinfo:
        parse_token(raw)
    assert HEADER not in str(excinfo.value)
    assert PAYLOAD not in str(excinfo.value)
    assert SIGNATURE not in str(excinfo.value)


def test_rejects_payload_nested_beyond_the_limit() -> None:
    payload: dict[str, object] = {"x": 1}
    for _ in range(50):
        payload = {"a": payload}
    with pytest.raises(TokenParseError, match="nested too deeply"):
        parse_token(build_token({"alg": "HS256"}, payload))
