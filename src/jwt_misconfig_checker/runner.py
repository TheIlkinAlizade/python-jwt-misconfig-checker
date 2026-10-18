from collections.abc import Iterable

from jwt_misconfig_checker.models import Check, CheckContext, Finding, ParsedToken
from jwt_misconfig_checker.registry import DEFAULT_CHECKS


def run_checks(
    token: ParsedToken,
    context: CheckContext,
    checks: Iterable[Check] = DEFAULT_CHECKS,
) -> list[Finding]:
    findings = [finding for check in checks for finding in check.run(token, context)]
    return sorted(findings, key=lambda finding: (-finding.severity, finding.check_id))
