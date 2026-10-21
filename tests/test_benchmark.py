"""Tests for the scorer, and a regression test on the shipped policy.

A scorer that miscounts flatters the policy, which is the one failure that
makes the whole repository worthless. The classification rules get tested
directly, and the shipped attack suite is re-scored so a policy edit that
loses coverage fails the build.
"""

from __future__ import annotations

import pathlib

import pytest

from benchmark.run import CaseResult, build_principals, run

ROOT = pathlib.Path(__file__).resolve().parent.parent
CASES = ROOT / "attacks" / "cases.yml"
POLICY = ROOT / "attacks" / "policy.yml"


def result(**kwargs):
    base = dict(
        id="X", title="t", severity="HIGH", owasp="LLM06",
        is_attack=True, succeeded_unguarded=True, succeeded_guarded=False,
        rule_id=None, reason="",
    )
    base.update(kwargs)
    return CaseResult(**base)


# --- classification ----------------------------------------------------------


def test_an_attack_that_worked_unguarded_and_is_now_denied_is_blocked():
    r = result(succeeded_unguarded=True, succeeded_guarded=False)
    assert r.blocked and not r.missed and not r.broken


def test_an_attack_that_still_succeeds_is_missed():
    r = result(succeeded_unguarded=True, succeeded_guarded=True)
    assert r.missed and not r.blocked


def test_an_attack_that_never_worked_is_not_counted_as_blocked():
    """Otherwise a suite padded with impossible attacks inflates the score.

    This is the specific way a block rate gets gamed: add cases that fail
    against any policy, including no policy, and watch the percentage climb.
    """
    r = result(succeeded_unguarded=False, succeeded_guarded=False)
    assert not r.blocked and not r.missed


def test_a_legitimate_call_that_is_denied_is_breakage():
    r = result(is_attack=False, succeeded_unguarded=True, succeeded_guarded=False)
    assert r.broken and not r.blocked


def test_a_legitimate_call_that_is_allowed_is_fine():
    r = result(is_attack=False, succeeded_guarded=True)
    assert not r.broken


# --- principals --------------------------------------------------------------


def test_anonymous_is_built_without_roles():
    principals = build_principals({"principals": {"anonymous": {"roles": []}}})
    assert principals["anonymous"].is_anonymous


def test_attributes_reach_the_principal_for_interpolation():
    principals = build_principals(
        {"principals": {"alice": {"roles": ["user"], "attributes": {"tenant": "acme"}}}})
    assert principals["alice"].attributes["tenant"] == "acme"


# --- the shipped suite -------------------------------------------------------


@pytest.fixture(scope="module")
def scored():
    return run(CASES, POLICY)


def test_the_shipped_policy_blocks_every_attack(scored):
    _, stats = scored
    assert stats["missed"] == 0, "an attack got through; see benchmark output"
    assert stats["block_rate"] == 1.0


def test_the_shipped_policy_breaks_no_legitimate_call(scored):
    """The half that is easy to forget.

    A policy of 'deny everything' scores a perfect block rate. These cases are
    what stop that being a passing grade, and they caught a real bug in the
    shipped policy: a guard rule written as `not_equals: ""` matched every
    path and denied all file access, while the attack suite still reported
    1.000.
    """
    _, stats = scored
    assert stats["broken"] == 0
    assert stats["legitimate_calls"] >= 4, "keep real traffic in the suite"


def test_every_attack_in_the_suite_actually_works_unguarded(scored):
    """A case that fails without a policy is measuring nothing."""
    results, _ = scored
    dead = [r.id for r in results if r.is_attack and not r.succeeded_unguarded]
    assert not dead, f"these attacks do not work even with no policy: {dead}"


def test_the_suite_covers_both_object_and_function_level_failures(scored):
    """BOLA and BFLA equivalents. A suite that only has one is only half a
    test of an authorization control."""
    results, _ = scored
    cwes = {r.id: r for r in results}
    assert any(r.is_attack for r in results), "sanity"
    # AUTHZ-01 is cross-principal object access; AUTHZ-05 is a role-gated tool.
    assert cwes["AUTHZ-01"].blocked
    assert cwes["AUTHZ-05"].blocked


def test_the_suite_has_a_meaningful_number_of_attacks(scored):
    _, stats = scored
    assert stats["attacks"] >= 10
