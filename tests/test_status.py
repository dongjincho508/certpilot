from datetime import datetime, timedelta

import pytest

from certpilot_core.status import (Status, classify, classify_chain_member, remaining_days, worst)

NOW = datetime(2026, 10, 28, 12, 0, 0)
NB = NOW - timedelta(days=100)


def test_ok_when_beyond_warn():  # AC-4
    assert classify(NB, NOW + timedelta(days=31), NOW) == Status.OK


def test_warn_boundary_inclusive():
    assert classify(NB, NOW + timedelta(days=30), NOW) == Status.WARN
    assert classify(NB, NOW + timedelta(days=30, seconds=1), NOW) == Status.OK


def test_expired_boundary_inclusive():
    assert classify(NB, NOW, NOW) == Status.EXPIRED
    assert classify(NB, NOW + timedelta(seconds=1), NOW) == Status.WARN


def test_not_yet_valid():
    assert classify(NOW + timedelta(seconds=1), NOW + timedelta(days=90), NOW) == Status.NOT_YET


def test_custom_warn_days():
    assert classify(NB, NOW + timedelta(days=45), NOW, warn_days=60) == Status.WARN


def test_remaining_days_floor_and_clamp():
    assert remaining_days(NOW + timedelta(days=2, hours=23), NOW) == 2
    assert remaining_days(NOW - timedelta(days=5), NOW) == 0


def test_chain_member_risk():
    assert classify_chain_member(NB, NOW + timedelta(days=400), NOW) == Status.OK
    assert classify_chain_member(NB, NOW + timedelta(days=10), NOW) == Status.CHAIN_RISK
    assert classify_chain_member(NB, NOW - timedelta(days=1), NOW) == Status.CHAIN_RISK


@pytest.mark.parametrize("statuses,expected", [
    ([Status.OK, Status.WARN], Status.WARN),
    ([Status.OK, Status.FETCH_FAIL], Status.FETCH_FAIL),
    ([Status.UNKNOWN, Status.NOT_FOUND], Status.NOT_FOUND),
    ([Status.WARN, Status.EXPIRED, Status.OK], Status.EXPIRED),
    ([Status.CHAIN_RISK, Status.NOT_YET], Status.CHAIN_RISK),
    ([], Status.NOT_FOUND),
])
def test_worst_aggregation(statuses, expected):  # Q-AGG
    assert worst(statuses) == expected
