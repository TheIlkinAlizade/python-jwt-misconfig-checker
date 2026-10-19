from collections import Counter
from collections.abc import Iterable, Sequence

from rich.console import Console
from rich.markup import escape

from jwt_misconfig_checker.models import Check, Finding, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def summary_line(findings: Sequence[Finding]) -> str:
    counts = Counter(finding.severity for finding in findings)
    parts = [
        f"{counts[severity]} {severity.name}" for severity in reversed(Severity) if counts[severity]
    ]
    return f"{len(findings)} finding(s): {', '.join(parts)}"


def render_human(
    findings: Sequence[Finding],
    checks: Iterable[Check],
    token_display: str,
    console: Console,
) -> None:
    by_id = {check.id: check for check in checks}
    console.print(f"Token: {escape(token_display)}", soft_wrap=True)
    if not findings:
        console.print("No findings.")
        return
    for finding in findings:
        check = by_id[finding.check_id]
        style = SEVERITY_STYLES[finding.severity]
        heading = (
            f"[{style}]{finding.severity.name}[/] {finding.check_id} {escape(finding.message)}"
        )
        console.print(f"\n{heading}", soft_wrap=True)
        console.print(f"  Where:    {escape(finding.location)}", soft_wrap=True)
        console.print(f"  Evidence: {escape(finding.evidence)}", soft_wrap=True)
        console.print(f"  Why:      {escape(check.description)}", soft_wrap=True)
        console.print(f"  Fix:      {escape(check.remediation)}", soft_wrap=True)
        console.print(f"  See:      {escape('; '.join(check.references))}", soft_wrap=True)
    console.print(f"\n{summary_line(findings)}")
