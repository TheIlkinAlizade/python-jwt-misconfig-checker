import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from jwt_misconfig_checker.checks.common import build_finding
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity
from jwt_misconfig_checker.redaction import describe_length, mask_email

MAX_DEPTH = 8
MAX_STRING_LENGTH = 2048
NAME_WORD_PATTERN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "passphrase"})
SECRET_WORDS = frozenset({"secret", "credential", "credentials", "apikey", "privatekey"})
SECRET_PAIRS = frozenset(
    {("api", "key"), ("private", "key"), ("access", "key"), ("client", "secret")}
)
PII_WORDS = frozenset({"ssn", "dob", "birthdate", "passport", "iban", "phone", "mobile"})


@dataclass(frozen=True)
class ValueRule:
    pattern: re.Pattern[str]
    label: str
    severity: Severity


VALUE_RULES = (
    ValueRule(re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key", Severity.HIGH),
    ValueRule(re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "an AWS access key id", Severity.HIGH),
    ValueRule(re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "a GitHub token", Severity.HIGH),
    ValueRule(
        re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"), "a Stripe secret key", Severity.HIGH
    ),
    ValueRule(re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "a Slack token", Severity.HIGH),
    ValueRule(re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "a Google API key", Severity.HIGH),
    ValueRule(
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
        "an embedded JWT",
        Severity.MEDIUM,
    ),
    ValueRule(
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "an email address",
        Severity.LOW,
    ),
)
CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def name_words(name: str) -> list[str]:
    return [word.lower() for word in NAME_WORD_PATTERN.findall(name)]


def is_luhn_valid(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        digit = int(char)
        if position % 2 == 1:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def has_card_number(value: str) -> bool:
    for match in CARD_PATTERN.finditer(value):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and is_luhn_valid(digits):
            return True
    return False


def walk(value: Any, path: str, depth: int = 0) -> Iterator[tuple[str, str, Any]]:
    if depth > MAX_DEPTH:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            yield child, str(key), item
            yield from walk(item, child, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child = f"{path}[{index}]"
            yield child, "", item
            yield from walk(item, child, depth + 1)


class SensitiveDataCheck:
    id = "JWT-DAT-001"
    title = "Sensitive data in the payload"
    severity = Severity.HIGH
    description = (
        "The payload contains fields or values that look like passwords, secrets, "
        "API keys, or personal data. A JWT payload is only encoded, so anyone who "
        "holds the token can read it, including logs, proxies, and browser tools."
    )
    remediation = (
        "Keep claims minimal: a subject identifier and the facts needed for "
        "authorization. Look up everything else server-side, and use encrypted JWTs "
        "(JWE) when claim confidentiality is required."
    )
    references: tuple[str, ...] = (
        "RFC 7519 section 8 (Security considerations: confidentiality)",
        "RFC 8725 section 3.12 (Avoid sensitive data in tokens)",
        "OWASP JWT Cheat Sheet: Sensitive information disclosure",
        "OWASP Top 10 A02:2021 Cryptographic Failures",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        findings = []
        for path, key, value in walk(token.payload, "payload"):
            findings.extend(self.assess_name(path, key, value))
            if isinstance(value, str):
                findings.extend(self.assess_value(path, value))
        return findings

    def assess_name(self, path: str, key: str, value: Any) -> list[Finding]:
        if isinstance(value, dict | list) or value in (None, "", False):
            return []
        words = name_words(key)
        pairs = set(zip(words, words[1:], strict=False))
        if PASSWORD_WORDS & set(words):
            return [self.report(Severity.HIGH, "A field is named like a password", path, value)]
        if SECRET_WORDS & set(words) or SECRET_PAIRS & pairs:
            return [self.report(Severity.MEDIUM, "A field is named like a secret", path, value)]
        if PII_WORDS & set(words):
            return [self.report(Severity.LOW, "A field is named like personal data", path, value)]
        return []

    def assess_value(self, path: str, value: str) -> list[Finding]:
        text = value[:MAX_STRING_LENGTH]
        findings = [
            self.report(rule.severity, f"A value looks like {rule.label}", path, text, rule.pattern)
            for rule in VALUE_RULES
            if rule.pattern.search(text)
        ]
        if has_card_number(text):
            findings.append(
                self.report(Severity.MEDIUM, "A value looks like a payment card number", path, text)
            )
        return findings

    def report(
        self,
        severity: Severity,
        message: str,
        path: str,
        value: Any,
        pattern: re.Pattern[str] | None = None,
    ) -> Finding:
        evidence = self.describe(value, pattern)
        return build_finding(self, severity, message, path, evidence)

    def describe(self, value: Any, pattern: re.Pattern[str] | None) -> str:
        if not isinstance(value, str):
            return f"{type(value).__name__} value"
        if pattern is not None and pattern.pattern.endswith(r"[A-Za-z]{2,}"):
            match = pattern.search(value)
            return mask_email(match.group()) if match else describe_length(value)
        return describe_length(value)
