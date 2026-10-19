MASK = "***"
VISIBLE_PREFIX = 8


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}{MASK}@{domain}"


def describe_length(value: str) -> str:
    return f"{MASK} ({len(value)} characters)"


def redact_token(token: str) -> str:
    cleaned = token.strip()
    return f"{cleaned[:VISIBLE_PREFIX]}{MASK} ({len(cleaned)} characters)"
