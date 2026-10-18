import re
from urllib.parse import unquote

from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity

MAX_REASONABLE_KID_LENGTH = 128

HIGH_RISK_PATTERNS = (
    (re.compile(r"(^|[\\/])\.\.($|[\\/])"), "it contains a path traversal sequence"),
    (re.compile(r"\x00"), "it contains a null byte"),
    (re.compile(r"^(/|[a-z]:[\\/])", re.IGNORECASE), "it is an absolute file path"),
    (re.compile(r"/dev/(null|zero|random|urandom)", re.IGNORECASE), "it names a device file"),
)
MEDIUM_RISK_PATTERNS = (
    (re.compile(r"'|\"|--|/\*|\*/"), "it contains SQL quote or comment characters"),
    (
        re.compile(r"\b(union|select|insert|update|delete|drop|sleep|benchmark)\b", re.IGNORECASE),
        "it contains SQL keywords",
    ),
    (re.compile(r"\bor\b\s+\S+\s*=\s*\S+", re.IGNORECASE), "it contains a SQL boolean condition"),
    (re.compile(r"[;|&`]|\$\("), "it contains shell metacharacters"),
)


def matching_reasons(value: str, patterns: tuple[tuple[re.Pattern[str], str], ...]) -> list[str]:
    candidates = {value, unquote(value)}
    return [
        reason
        for pattern, reason in patterns
        if any(pattern.search(candidate) for candidate in candidates)
    ]


class KidInjectionCheck:
    id = "JWT-HDR-003"
    title = "Suspicious kid header"
    severity = Severity.HIGH
    description = (
        "The kid header contains content that looks like path traversal, SQL, or "
        "command injection. A verifier that builds a file path, query, or command "
        "from kid can be steered into loading a key the attacker controls."
    )
    remediation = (
        "Treat kid as an opaque identifier. Match it by equality against a fixed set "
        "of known keys, use parameterized queries, and never concatenate it into a "
        "path or command. Reject values that do not match a strict identifier pattern."
    )
    references: tuple[str, ...] = (
        "RFC 7515 section 4.1.4 (kid header parameter)",
        "RFC 8725 section 3.10 (Validate the kid value)",
        "OWASP JWT Cheat Sheet: Injection through the kid header",
        "OWASP Path Traversal and SQL Injection guidance",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        if "kid" not in token.header:
            return []
        value = token.header["kid"]
        if not isinstance(value, str):
            message = "The kid header is not a string"
            return [self.report(Severity.LOW, message, type(value).__name__)]
        return self.assess(value)

    def assess(self, value: str) -> list[Finding]:
        high = matching_reasons(value, HIGH_RISK_PATTERNS)
        medium = matching_reasons(value, MEDIUM_RISK_PATTERNS)
        if high or medium:
            severity = Severity.HIGH if high else Severity.MEDIUM
            message = f"The kid header looks like an injection attempt: {', '.join(high + medium)}"
            return [self.report(severity, message, value)]
        if len(value) > MAX_REASONABLE_KID_LENGTH:
            return [self.report(Severity.LOW, "The kid header is unusually long", value)]
        return []

    def report(self, severity: Severity, message: str, evidence: str) -> Finding:
        return build_finding(self, severity, message, "header.kid", safe_evidence(evidence))