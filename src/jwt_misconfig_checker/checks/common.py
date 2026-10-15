from jwt_misconfig_checker.models import Check, Finding, Severity

MAX_EVIDENCE_LENGTH = 64


def safe_evidence(value: str) -> str:
    return ascii(value)[:MAX_EVIDENCE_LENGTH]


def build_finding(
    check: Check, severity: Severity, message: str, location: str, evidence: str
) -> Finding:
    return Finding(
        check_id=check.id,
        severity=severity,
        message=message,
        location=location,
        evidence=evidence,
    )