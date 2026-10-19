from jwt_misconfig_checker.checks.common import build_finding
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity

ASYMMETRIC_PREFIXES = ("RS", "PS", "ES")
ASYMMETRIC_NAMES = frozenset({"EdDSA"})
KEY_REFERENCE_HEADERS = ("kid", "jku", "x5u")
EMBEDDED_KEY_HEADERS = ("jwk", "x5c")


def is_asymmetric(algorithm: object) -> bool:
    if not isinstance(algorithm, str):
        return False
    return algorithm in ASYMMETRIC_NAMES or (
        algorithm.startswith(ASYMMETRIC_PREFIXES) and algorithm[2:].isdigit()
    )


class AlgorithmConfusionCheck:
    id = "JWT-ALG-003"
    title = "Algorithm confusion exposure (RS256 to HS256)"
    severity = Severity.MEDIUM
    description = (
        "The token uses an asymmetric algorithm, so a public key exists. A verifier "
        "that takes the algorithm from the token and passes its public key to a "
        "generic verify call can be tricked into treating that public key as an HMAC "
        "secret, letting an attacker forge tokens by switching alg to HS256. This is "
        "a risk assessment: the token alone cannot show whether the verifier is "
        "vulnerable."
    )
    remediation = (
        "Pin the expected algorithm in the verifier and bind it to the key type. Never "
        "read the algorithm from the token. Pass an explicit allowlist such as "
        "algorithms=['RS256'], and use library APIs that reject a key whose type does "
        "not match the algorithm."
    )
    references: tuple[str, ...] = (
        "RFC 8725 section 3.1 (Perform algorithm verification)",
        "RFC 8725 section 2.1 (Weak signatures and insufficient signature validation)",
        "CVE-2015-9235 (jsonwebtoken algorithm confusion)",
        "OWASP JWT Cheat Sheet: Algorithm confusion",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        algorithm = token.header.get("alg")
        if not is_asymmetric(algorithm):
            return []
        references = [name for name in KEY_REFERENCE_HEADERS if name in token.header]
        embedded = [name for name in EMBEDDED_KEY_HEADERS if name in token.header]
        return [self.assess(str(algorithm), references, embedded)]

    def assess(self, algorithm: str, references: list[str], embedded: list[str]) -> Finding:
        if embedded:
            severity = Severity.MEDIUM
            message = "A public key travels with the token, which widens confusion attacks"
        elif references:
            severity = Severity.LOW
            message = "The verifier resolves keys by reference, so a wrong-type key may be reused"
        else:
            severity = Severity.INFO
            message = "Asymmetric token: servers must pin the algorithm to avoid HS256 confusion"
        signals = ", ".join([f"alg={algorithm}", *references, *embedded])
        return build_finding(self, severity, message, "header.alg", signals)
