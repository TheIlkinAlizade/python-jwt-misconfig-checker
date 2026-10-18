from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity


class IdentityClaimsCheck:
    id = "JWT-CLM-002"
    title = "Missing issuer or audience claim"
    severity = Severity.MEDIUM
    description = (
        "The token has no iss or aud claim, or they have an unexpected shape. Without "
        "them a verifier cannot tell who issued the token or which service it was "
        "meant for, which allows token substitution across services."
    )
    remediation = (
        "Issue tokens with iss and aud, and configure every verifier to require the "
        "expected issuer and its own audience value."
    )
    references: tuple[str, ...] = (
        "RFC 7519 sections 4.1.1 and 4.1.3 (iss, aud)",
        "RFC 8725 sections 3.8 and 3.9 (Validate issuer and audience)",
        "OWASP JWT Cheat Sheet: Token substitution",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        findings = []
        for name in ("iss", "aud"):
            if name not in token.payload:
                message = f"The token has no {name} claim"
                findings.append(self.report(Severity.MEDIUM, message, name, "<absent>"))
            elif not self.is_well_formed(name, token.payload[name]):
                message = f"The {name} claim has an unexpected type or is empty"
                evidence = safe_evidence(str(token.payload[name]))
                findings.append(self.report(Severity.LOW, message, name, evidence))
        return findings

    def is_well_formed(self, name: str, value: object) -> bool:
        if isinstance(value, str):
            return value != ""
        if name == "aud" and isinstance(value, list):
            return bool(value) and all(isinstance(item, str) and item for item in value)
        return False

    def report(self, severity: Severity, message: str, name: str, evidence: str) -> Finding:
        return build_finding(self, severity, message, f"payload.{name}", evidence)
