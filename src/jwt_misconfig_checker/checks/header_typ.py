from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity

EXPECTED_TYPES = frozenset({"jwt", "at+jwt", "jose"})


class HeaderTypCheck:
    id = "JWT-HDR-001"
    title = "Unexpected typ header"
    severity = Severity.LOW
    description = (
        "The typ header is present but is not a recognized JWT media type. Without "
        "explicit typing, a token minted for one purpose can be replayed in another."
    )
    remediation = (
        "Use explicit typing such as 'at+jwt' for access tokens and have each "
        "verifier reject tokens whose typ does not match its purpose."
    )
    references: tuple[str, ...] = (
        "RFC 7519 section 5.1 (typ header parameter)",
        "RFC 8725 section 3.11 (Use explicit typing)",
        "RFC 9068 (JWT profile for OAuth 2.0 access tokens)",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        if "typ" not in token.header:
            return []
        media_type = token.header["typ"]
        if not isinstance(media_type, str):
            message = "The typ header is not a string"
            return [self.report(Severity.LOW, message, type(media_type).__name__)]
        if media_type.lower().removeprefix("application/") not in EXPECTED_TYPES:
            return [self.report(Severity.INFO, "The typ header is unexpected", media_type)]
        return []

    def report(self, severity: Severity, message: str, evidence: str) -> Finding:
        return build_finding(self, severity, message, "header.typ", safe_evidence(evidence))