"""Auditor check C: MPC-signed authorizations against USDC's authorizationState (simulated USDC)."""
from spend_guard.auditor import FAILED, SETTLED, SIGNED, check_signed

PAYER = "0x00000000000000000000000000000000000000c3"
NOW = 1_800_000_000


class FakeUsdc:
    def __init__(self, used):
        self.used, self.asked = set(used), []

    def authorization_state(self, authorizer, nonce):
        self.asked.append((authorizer, nonce))
        return nonce in self.used


def case(status, used, valid_before=NOW - 60):
    reqs = [{"id": 1, "status": status}]
    sigreqs = [{"id": 1, "payer": PAYER, "nonce": "aa" * 32, "valid_before": valid_before}]
    usdc = FakeUsdc({"0x" + "aa" * 32} if used else ())
    problems, notes = check_signed(reqs, sigreqs, usdc, NOW)
    assert usdc.asked == [(PAYER, "0x" + "aa" * 32)]
    return problems, notes


def test_settled_and_executed_is_consistent():
    assert case(SETTLED, used=True) == ([], [])


def test_settled_but_never_executed_is_a_problem():
    problems, _ = case(SETTLED, used=False)
    assert len(problems) == 1 and "never executed" in problems[0]


def test_attester_released_an_executed_authorization():
    problems, _ = case(FAILED, used=True)
    assert len(problems) == 1 and "released by the attester" in problems[0]


def test_attester_released_an_unused_authorization():
    assert case(FAILED, used=False) == ([], [])


def test_executed_but_never_recorded_is_a_problem():
    problems, _ = case(SIGNED, used=True)
    assert len(problems) == 1 and "never recorded" in problems[0]


def test_expired_unused_waits_for_the_attester():
    problems, notes = case(SIGNED, used=False)
    assert problems == [] and "waiting for the attester" in notes[0]


def test_still_valid_signature_is_not_judged_yet():
    assert case(SIGNED, used=True, valid_before=NOW + 60) == ([], [])


def test_signature_of_a_request_outside_the_audit_range_is_skipped():
    usdc = FakeUsdc(())
    assert check_signed([], [{"id": 9, "payer": PAYER, "nonce": "bb" * 32, "valid_before": 0}], usdc, NOW) == ([], [])
    assert usdc.asked == []
