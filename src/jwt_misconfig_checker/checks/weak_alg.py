from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity

STANDARD_ALGORITHMS = (
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
)
STANDARD_BY_UPPERCASE = {name.upper(): name for name in STANDARD_ALGORITHMS}
WEAK_DIGEST_ALGORITHMS = frozenset(
    {"HS1", "RS1", "ES1", "PS1", "HS224", "RS224", "MD5", "HMACMD5", "HMACSHA1"}
)
KEY_MANAGEMENT_ALGORITHMS = frozenset(
    {
        "RSA1_5",
        "RSA-OAEP",
        "RSA-OAEP-256",
        "DIR",
        "A128KW",
        "A192KW",
        "A256KW",
        "A128GCMKW",
        "A192GCMKW",
        "A256GCMKW",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    }
)


class WeakAlgorithmCheck:
    id = "JWT-ALG-002"
    title = "Weak, unexpected, or non-standard signing algorithm"
    severity = Severity.HIGH
    description = (
        "The alg header names something other than a registered signing algorithm: "
        "a weak digest, an encryption key-management algorithm, a non-standard "
        "capitalization, or an unknown value. Verifiers that accept such values "
        "normalize or fall back in ways attackers can exploit."
    )
    remediation = (
        "Verify with a fixed allowlist of strong algorithms such as RS256, ES256, "
        "or EdDSA, and reject any token whose alg is not an exact match."
    )
    references: tuple[str, ...] = (
        "RFC 7518 section 3.1 (Signature algorithm registry)",
        "RFC 8725 section 3.1 (Perform algorithm verification)",
        "RFC 8725 section 3.2 (Use appropriate algorithms)",
        "OWASP JWT Cheat Sheet: Token sidejacking and algorithm handling",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        algorithm = token.header.get("alg")
        if not isinstance(algorithm, str) or algorithm.lower() == "none":
            return []
        return self.assess(algorithm)

    def assess(self, algorithm: str) -> list[Finding]:
        if algorithm in STANDARD_ALGORITHMS:
            return []
        normalized = algorithm.upper()
        if normalized in WEAK_DIGEST_ALGORITHMS:
            return [self.report(Severity.HIGH, "The alg names a weak digest", algorithm)]
        if normalized in KEY_MANAGEMENT_ALGORITHMS:
            message = "The alg is an encryption algorithm in a signed token"
            return [self.report(Severity.MEDIUM, message, algorithm)]
        if normalized in STANDARD_BY_UPPERCASE:
            message = "The alg uses non-standard capitalization"
            return [self.report(Severity.MEDIUM, message, algorithm)]
        return [self.report(Severity.LOW, "The alg is not a registered algorithm", algorithm)]

    def report(self, severity: Severity, message: str, algorithm: str) -> Finding:
        return build_finding(self, severity, message, "header.alg", safe_evidence(algorithm))
