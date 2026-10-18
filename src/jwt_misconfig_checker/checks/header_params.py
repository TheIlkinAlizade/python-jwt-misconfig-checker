import ipaddress
from urllib.parse import urlsplit

from jwt_misconfig_checker.checks.common import build_finding, safe_evidence
from jwt_misconfig_checker.models import CheckContext, Finding, ParsedToken, Severity

EMBEDDED_KEY_PARAMETERS = {
    "jwk": "an embedded public key",
    "x5c": "an embedded certificate chain",
}
KEY_URL_PARAMETERS = {
    "jku": "a JWKS URL",
    "x5u": "a certificate URL",
}
LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})
LOCAL_SUFFIXES = (".local", ".internal", ".localhost")


def is_private_host(host: str) -> bool:
    if host in LOCAL_HOSTNAMES or host.endswith(LOCAL_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def url_risks(value: str) -> list[str]:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
    except ValueError:
        return ["the URL cannot be parsed"]
    risks = []
    if parts.scheme.lower() != "https":
        risks.append("the scheme is not https")
    if not host:
        risks.append("the URL has no host")
    elif is_private_host(host.lower()):
        risks.append("the host is local or private")
    if parts.username or parts.password:
        risks.append("the URL embeds credentials")
    return risks


class HeaderParametersCheck:
    id = "JWT-HDR-002"
    title = "Header parameter that lets the token supply its own key"
    severity = Severity.HIGH
    description = (
        "The header carries jwk, x5c, jku, or x5u. These let a token embed a key or "
        "point the verifier at a key source chosen by whoever created the token. A "
        "verifier that trusts them accepts forged tokens, and URL parameters also "
        "enable server-side request forgery."
    )
    remediation = (
        "Ignore jwk, x5c, jku, and x5u. Resolve verification keys from your own "
        "configuration using the kid header, and if URLs must be honored, allow only "
        "exact, pre-approved https addresses."
    )
    references: tuple[str, ...] = (
        "RFC 7515 sections 4.1.2 to 4.1.6 (jku, jwk, x5u, x5c)",
        "RFC 8725 section 3.5 (Do not trust embedded keys)",
        "OWASP JWT Cheat Sheet: Incorrect composition of encryption and signature",
        "CVE-2018-0114 (node-jose embedded jwk)",
    )

    def run(self, token: ParsedToken, context: CheckContext) -> list[Finding]:
        findings = []
        for name, label in EMBEDDED_KEY_PARAMETERS.items():
            if name in token.header:
                message = f"The header carries {label}"
                findings.append(self.report(Severity.HIGH, message, name, "present"))
        for name, label in KEY_URL_PARAMETERS.items():
            if name in token.header:
                findings.extend(self.assess_url(name, label, token.header[name]))
        return findings

    def assess_url(self, name: str, label: str, value: object) -> list[Finding]:
        if not isinstance(value, str):
            message = f"The {name} header is not a string"
            return [self.report(Severity.LOW, message, name, type(value).__name__)]
        risks = url_risks(value)
        if risks:
            message = f"The header carries {label} that is risky: {', '.join(risks)}"
            return [self.report(Severity.HIGH, message, name, value)]
        message = f"The header carries {label}"
        return [self.report(Severity.MEDIUM, message, name, value)]

    def report(self, severity: Severity, message: str, name: str, evidence: str) -> Finding:
        return build_finding(self, severity, message, f"header.{name}", safe_evidence(evidence))
