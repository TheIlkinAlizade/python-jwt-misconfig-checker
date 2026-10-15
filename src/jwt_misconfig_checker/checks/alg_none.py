from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity


class AlgNoneCheck:
    id = "JWT-ALG-001"
    title = "Unsecured token or invalid algorithm declaration"
    severity = Severity.CRITICAL
    description = (
        "The header declares the 'none' algorithm, which means the token carries no "
        "signature. A server that lets the token choose its own verification method "
        "will accept forged tokens with any claims."
    )
    remediation = (
        "Configure the verifier with a fixed allowlist of algorithms and never derive "
        "the algorithm from the token. Reject 'none' unconditionally."
    )
    references: tuple[str, ...] = (
        "RFC 7519 section 6 (Unsecured JWTs)",
        "RFC 8725 section 3.2 (Do not trust the alg header)",
        "OWASP JWT Cheat Sheet: None hashing algorithm",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        if "alg" not in token.header:
            return [self.report(Severity.HIGH, "The alg header is missing", "<absent>")]
        algorithm = token.header["alg"]
        if not isinstance(algorithm, str):
            return [
                self.report(
                    Severity.HIGH, "The alg header is not a string", type(algorithm).__name__
                )
            ]
        if algorithm.lower() == "none":
            message = "The token declares alg none"
            return [self.report(Severity.CRITICAL, message, safe_evidence(algorithm))]
        return []

    def report(self, severity: Severity, message: str, evidence: str) -> Finding:
        return build_finding(self, severity, message, "header.alg", evidence)