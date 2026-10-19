import json
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any

from jwt_misconfig_checker import __version__
from jwt_misconfig_checker.models import Check, Finding, Severity


def finding_to_dict(finding: Finding, check: Check) -> dict[str, Any]:
    return {
        "id": finding.check_id,
        "title": check.title,
        "severity": finding.severity.name,
        "message": finding.message,
        "location": finding.location,
        "evidence": finding.evidence,
        "description": check.description,
        "remediation": check.remediation,
        "references": list(check.references),
    }


def render_json(
    findings: Sequence[Finding],
    checks: Iterable[Check],
    token_display: str,
) -> str:
    by_id = {check.id: check for check in checks}
    counts = Counter(finding.severity for finding in findings)
    report = {
        "tool": "jwt-misconfig-check",
        "version": __version__,
        "token": token_display,
        "summary": {
            "total": len(findings),
            "by_severity": {severity.name: counts[severity] for severity in reversed(Severity)},
        },
        "findings": [finding_to_dict(finding, by_id[finding.check_id]) for finding in findings],
    }
    return json.dumps(report, indent=2)
