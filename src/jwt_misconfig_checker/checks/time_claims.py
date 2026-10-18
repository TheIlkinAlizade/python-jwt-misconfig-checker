from datetime import UTC, datetime, timedelta

from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity

CLOCK_SKEW_LEEWAY = timedelta(seconds=60)
LONG_LIFETIME = timedelta(hours=24)
EXCESSIVE_LIFETIME = timedelta(days=30)
TIME_CLAIMS = ("exp", "nbf", "iat")


def as_datetime(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return None


class TimeClaimsCheck:
    id = "JWT-CLM-001"
    title = "Missing or unsafe time claims"
    severity = Severity.HIGH
    description = (
        "The token has no expiry, an excessive lifetime, is already expired, or "
        "carries nbf or iat values that do not make sense. Tokens that never expire "
        "stay useful to anyone who steals them."
    )
    remediation = (
        "Always issue exp with a short lifetime, validate exp, nbf, and iat on every "
        "request, and use refresh tokens for long sessions."
    )
    references: tuple[str, ...] = (
        "RFC 7519 sections 4.1.4 to 4.1.6 (exp, nbf, iat)",
        "RFC 8725 section 3.8 (Validate all claims)",
        "OWASP JWT Cheat Sheet: Token lifetime and revocation",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        now = context.now()
        findings = self.invalid_types(token)
        findings += self.assess_exp(token, now)
        findings += self.assess_future(token, now, "nbf", "The token is not valid yet")
        findings += self.assess_future(token, now, "iat", "The token was issued in the future")
        return findings

    def invalid_types(self, token: ParsedToken) -> list[Finding]:
        return [
            self.report(
                Severity.MEDIUM,
                f"The {name} claim is not a valid numeric date",
                name,
                safe_evidence(str(token.payload[name])),
            )
            for name in TIME_CLAIMS
            if name in token.payload and as_datetime(token.payload[name]) is None
        ]

    def assess_exp(self, token: ParsedToken, now: datetime) -> list[Finding]:
        if "exp" not in token.payload:
            return [self.report(Severity.HIGH, "The token has no expiry", "exp", "<absent>")]
        expiry = as_datetime(token.payload["exp"])
        if expiry is None:
            return []
        if expiry <= now:
            return [self.report(Severity.MEDIUM, "The token is expired", "exp", expiry.isoformat())]
        return self.assess_lifetime(token, expiry, now)

    def assess_lifetime(self, token: ParsedToken, expiry: datetime, now: datetime) -> list[Finding]:
        issued = as_datetime(token.payload.get("iat")) or now
        lifetime = expiry - issued
        if lifetime > EXCESSIVE_LIFETIME:
            return [self.report(Severity.HIGH, "The token lifetime exceeds 30 days", "exp", str(lifetime))]
        if lifetime > LONG_LIFETIME:
            return [self.report(Severity.MEDIUM, "The token lifetime exceeds 24 hours", "exp", str(lifetime))]
        return []

    def assess_future(
        self, token: ParsedToken, now: datetime, name: str, message: str
    ) -> list[Finding]:
        moment = as_datetime(token.payload.get(name))
        if moment is not None and moment > now + CLOCK_SKEW_LEEWAY:
            return [self.report(Severity.MEDIUM, message, name, moment.isoformat())]
        return []

    def report(self, severity: Severity, message: str, name: str, evidence: str) -> Finding:
        return build_finding(self, severity, message, f"payload.{name}", evidence)