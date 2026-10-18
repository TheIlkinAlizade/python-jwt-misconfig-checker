MASK = "***"


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}{MASK}@{domain}"


def describe_length(value: str) -> str:
    return f"{MASK} ({len(value)} characters)"


def describe_token(token: str) -> str:
    return f"{token[:6]}{MASK}" if len(token) > 12 else MASK
