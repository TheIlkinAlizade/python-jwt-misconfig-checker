from datetime import UTC, datetime

import pytest

from jwt_misconfig_checker.checks.time_claims import TimeClaimsCheck
from jwt_misconfig_checker.models import CheckContext, Severity
from tests.checks.helpers import run_check

CHECK = TimeClaimsCheck()
NOW = datetime(2026, 1, 1, tzinfo=UTC)
NOW_SECONDS = int(NOW.timestamp())
CONTEXT = CheckContext(now=lambda: NOW)
HOUR = 3600
DAY = 24 * HOUR


def severities(payload: dict[str, object]) -> list[Severity]:
    findings = run_check(CHECK, {"alg": "RS256"}, payload, context=CONTEXT)
    return [finding.severity for finding in findings]


def test_short_lived_token_is_clean() -> None:
    payload = {"iat": NOW_SECONDS, "exp": NOW_SECONDS + 15 * 60}
    assert severities(payload) == []


def test_missing_exp_is_high() -> None:
    assert severities({"iat": NOW_SECONDS}) == [Severity.HIGH]


def test_expired_token_is_medium() -> None:
    assert severities({"exp": NOW_SECONDS - 1}) == [Severity.MEDIUM]


def test_exp_equal_to_now_counts_as_expired() -> None:
    assert severities({"exp": NOW_SECONDS}) == [Severity.MEDIUM]


def test_lifetime_over_24_hours_is_medium() -> None:
    payload = {"iat": NOW_SECONDS, "exp": NOW_SECONDS + 2 * DAY}
    assert severities(payload) == [Severity.MEDIUM]


def test_lifetime_over_30_days_is_high() -> None:
    payload = {"iat": NOW_SECONDS, "exp": NOW_SECONDS + 90 * DAY}
    assert severities(payload) == [Severity.HIGH]


def test_lifetime_without_iat_is_measured_from_now() -> None:
    assert severities({"exp": NOW_SECONDS + 90 * DAY}) == [Severity.HIGH]


def test_iat_in_the_future_is_medium() -> None:
    payload = {"iat": NOW_SECONDS + HOUR, "exp": NOW_SECONDS + 2 * HOUR}
    assert severities(payload) == [Severity.MEDIUM]


def test_iat_within_clock_skew_is_tolerated() -> None:
    payload = {"iat": NOW_SECONDS + 30, "exp": NOW_SECONDS + 900}
    assert severities(payload) == []


def test_nbf_in_the_future_is_medium() -> None:
    payload = {"nbf": NOW_SECONDS + HOUR, "exp": NOW_SECONDS + 2 * HOUR}
    assert severities(payload) == [Severity.MEDIUM]


@pytest.mark.parametrize("name", ["exp", "nbf", "iat"])
@pytest.mark.parametrize("value", ["soon", None, True, [1], {"a": 1}, 10**30, 10**400, -(10**30)])
def test_invalid_time_values_do_not_crash(name: str, value: object) -> None:
    payload: dict[str, object] = {"exp": NOW_SECONDS + 900, name: value}
    findings = run_check(CHECK, {"alg": "RS256"}, payload, context=CONTEXT)
    assert any("not a valid numeric date" in finding.message for finding in findings)


def test_fractional_timestamps_are_accepted() -> None:
    payload = {"iat": NOW_SECONDS + 0.5, "exp": NOW_SECONDS + 900.5}
    assert severities(payload) == []


def test_locations_point_at_the_payload() -> None:
    findings = run_check(CHECK, {"alg": "RS256"}, {}, context=CONTEXT)
    assert findings[0].location == "payload.exp"