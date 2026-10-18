import hmac
import itertools
from collections.abc import Iterable, Iterator
from pathlib import Path

from jwt_misconfig_checker.checks.common import build_finding
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity
from jwt_misconfig_checker.redaction import describe_length

HMAC_DIGESTS = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
MAX_CANDIDATES = 5_000_000


def read_wordlist(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        for line in itertools.islice(handle, MAX_CANDIDATES):
            yield line.rstrip(b"\r\n")


class WeakSecretCheck:
    id = "JWT-SEC-001"
    title = "HMAC secret found in a wordlist"
    severity = Severity.CRITICAL
    description = (
        "The token signature matches an HMAC computed with a word from the supplied "
        "wordlist. Anyone holding one token can recover a weak secret offline and "
        "then sign tokens with any claims."
    )
    remediation = (
        "Replace the secret with at least 256 random bits from a secrets manager and "
        "rotate it, or use asymmetric keys when several parties verify tokens."
    )
    references: tuple[str, ...] = (
        "RFC 7518 section 3.2 (HMAC key strength)",
        "RFC 8725 section 3.5 (Use sufficiently strong keys)",
        "OWASP JWT Cheat Sheet: Weak token secret",
    )

    def __init__(self, candidates: Iterable[bytes]) -> None:
        self.candidates = candidates

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        algorithm = token.header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in HMAC_DIGESTS:
            return []
        digest = HMAC_DIGESTS[algorithm]
        for candidate in self.candidates:
            expected = hmac.digest(candidate, token.signing_input, digest)
            if hmac.compare_digest(expected, token.signature):
                return [self.report(candidate)]
        return []

    def report(self, secret: bytes) -> Finding:
        evidence = describe_length(secret.decode("utf-8", "replace"))
        message = "The HMAC secret is present in the supplied wordlist"
        return build_finding(self, Severity.CRITICAL, message, "signature", evidence)
