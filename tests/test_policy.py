"""Tests for the policy engine.

This is the security boundary, so the tests concentrate on the ways a policy
engine silently grants more than its author intended. Every one of these is a
real failure mode in shipped authorization code, not a hypothetical:

  - a constraint quietly dropped because an operator name was misspelled
  - a constraint satisfied vacuously because the argument was absent
  - a path check defeated by `..`
  - a deny overridden by a later allow
  - a regex anchored with `search` instead of `fullmatch`

Each of those turns a policy that reads correctly into one that is not.
"""

from __future__ import annotations

import pytest

from src.normalize import Principal, ToolCall
from src.policy import OPERATORS, Policy, PolicyError

ALICE = Principal(id="alice", roles=frozenset({"user"}))
BOB = Principal(id="bob", roles=frozenset({"user"}))
ROOT = Principal(id="root", roles=frozenset({"admin", "user"}))
ANON = Principal.anonymous()


def call(tool="read_file", arguments=None, principal=ALICE):
    return ToolCall(tool=tool, arguments=arguments or {}, principal=principal)


def policy(text: str) -> Policy:
    return Policy.from_yaml(text)


# --- deny by default ---------------------------------------------------------


def test_empty_policy_denies_everything():
    p = policy("version: 1\ndefault: deny\nrules: []\n")
    d = p.evaluate(call())
    assert not d.allowed
    assert d.rule_id is None


def test_a_tool_the_policy_never_mentions_is_denied():
    p = policy("""
default: deny
rules:
  - id: r
    tools: [read_file]
    roles: [user]
""")
    assert p.evaluate(call(tool="read_file")).allowed
    assert not p.evaluate(call(tool="execute_shell")).allowed


def test_allow_by_default_is_not_offered():
    """A gate whose default is allow is not a gate."""
    with pytest.raises(PolicyError, match="allow-by-default is not supported"):
        policy("default: allow\nrules: []\n")


# --- the failure modes -------------------------------------------------------


def test_a_misspelled_operator_is_rejected_at_load_rather_than_ignored():
    """Silently dropping an unknown constraint widens the rule."""
    with pytest.raises(PolicyError, match="unknown operator 'startswith'"):
        policy("""
default: deny
rules:
  - id: r
    tools: [read_file]
    arguments:
      path: { startswith: /home/alice }
""")


def test_a_constraint_on_a_missing_argument_does_not_match():
    """Otherwise a call slips the constraint by omitting the field."""
    p = policy("""
default: deny
rules:
  - id: r
    tools: [delete_file]
    roles: [user]
    arguments:
      path: { under_path: /home/alice }
""")
    assert p.evaluate(call(tool="delete_file", arguments={"path": "/home/alice/x"})).allowed
    assert not p.evaluate(call(tool="delete_file", arguments={})).allowed


def test_under_path_resolves_traversal():
    """`starts_with` permits /home/alice/../bob. under_path must not."""
    p = policy("""
default: deny
rules:
  - id: r
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: /home/alice }
""")
    assert p.evaluate(call(arguments={"path": "/home/alice/notes"})).allowed
    assert not p.evaluate(call(arguments={"path": "/home/alice/../bob/secret"})).allowed
    assert not p.evaluate(call(arguments={"path": "/home/alice/../../etc/shadow"})).allowed


def test_under_path_is_not_a_string_prefix():
    """/home/alice-backup must not count as inside /home/alice."""
    p = policy("""
default: deny
rules:
  - id: r
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: /home/alice }
""")
    assert not p.evaluate(call(arguments={"path": "/home/alice-backup/secret"})).allowed


def test_deny_wins_over_a_later_allow():
    """Otherwise the result depends on rule order."""
    p = policy("""
default: deny
rules:
  - id: deny-etc
    effect: deny
    tools: ["*"]
    arguments:
      path: { under_path: /etc }
  - id: allow-all-reads
    effect: allow
    tools: [read_file]
    roles: [user]
""")
    assert p.evaluate(call(arguments={"path": "/home/alice/x"})).allowed
    assert not p.evaluate(call(arguments={"path": "/etc/shadow"})).allowed


def test_deny_wins_over_an_earlier_allow_too():
    """Order independence runs both ways."""
    p = policy("""
default: deny
rules:
  - id: allow-all-reads
    effect: allow
    tools: [read_file]
    roles: [user]
  - id: deny-etc
    effect: deny
    tools: ["*"]
    arguments:
      path: { under_path: /etc }
""")
    assert not p.evaluate(call(arguments={"path": "/etc/shadow"})).allowed


def test_matches_is_anchored():
    """`search` would accept ../../etc/passwd#user-1."""
    p = policy("""
default: deny
rules:
  - id: r
    tools: [send_email]
    roles: [user]
    arguments:
      to: { matches: "[^@]+@corp\\\\.example" }
""")
    assert p.evaluate(call(tool="send_email", arguments={"to": "bob@corp.example"})).allowed
    assert not p.evaluate(
        call(tool="send_email", arguments={"to": "bob@corp.example.attacker.test"})).allowed
    assert not p.evaluate(
        call(tool="send_email", arguments={"to": "x@attacker.test?cc=bob@corp.example"})).allowed


# --- principal interpolation -------------------------------------------------


def test_interpolation_scopes_one_rule_to_every_user():
    p = policy("""
default: deny
rules:
  - id: own-files
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: "/home/{principal.id}" }
""")
    assert p.evaluate(call(arguments={"path": "/home/alice/x"}, principal=ALICE)).allowed
    assert p.evaluate(call(arguments={"path": "/home/bob/x"}, principal=BOB)).allowed
    assert not p.evaluate(call(arguments={"path": "/home/bob/x"}, principal=ALICE)).allowed


def test_interpolating_an_attribute():
    p = policy("""
default: deny
rules:
  - id: tenant-scoped
    tools: [read_record]
    roles: [user]
    arguments:
      tenant: { equals: "{principal.attributes.tenant}" }
""")
    acme = Principal(id="u1", roles=frozenset({"user"}), attributes={"tenant": "acme"})
    assert p.evaluate(ToolCall("read_record", {"tenant": "acme"}, acme)).allowed
    assert not p.evaluate(ToolCall("read_record", {"tenant": "globex"}, acme)).allowed


def test_a_missing_attribute_raises_rather_than_matching_literally():
    """Interpolating to the literal '{principal.attributes.tenant}' would
    quietly never match, which looks like a working deny but is a broken rule."""
    p = policy("""
default: deny
rules:
  - id: r
    tools: [read_record]
    roles: [user]
    arguments:
      tenant: { equals: "{principal.attributes.tenant}" }
""")
    with pytest.raises(PolicyError, match="has no attribute"):
        p.evaluate(ToolCall("read_record", {"tenant": "acme"}, ALICE))


def test_only_principal_may_be_interpolated():
    """Interpolating an argument would let a constraint match itself."""
    p = policy("""
default: deny
rules:
  - id: r
    tools: [read_file]
    roles: [user]
    arguments:
      path: { equals: "{arguments.path}" }
""")
    with pytest.raises(PolicyError, match="only principal"):
        p.evaluate(call(arguments={"path": "/anything"}))


# --- roles -------------------------------------------------------------------


def test_role_gating():
    p = policy("""
default: deny
rules:
  - id: admin-only
    tools: [grant_role]
    roles: [admin]
""")
    assert p.evaluate(call(tool="grant_role", principal=ROOT)).allowed
    assert not p.evaluate(call(tool="grant_role", principal=ALICE)).allowed


def test_anonymous_has_no_roles_and_so_matches_no_role_gated_rule():
    p = policy("""
default: deny
rules:
  - id: users-only
    tools: [read_file]
    roles: [user]
""")
    assert not p.evaluate(call(principal=ANON)).allowed


def test_a_rule_with_no_roles_applies_to_everyone_including_anonymous():
    """Documented behaviour, and a sharp edge: omitting roles is not a
    restriction, so a rule that forgets them is open to unauthenticated
    callers."""
    p = policy("""
default: deny
rules:
  - id: public
    tools: [get_status]
""")
    assert p.evaluate(call(tool="get_status", principal=ANON)).allowed


# --- policy hygiene ----------------------------------------------------------


def test_duplicate_rule_ids_are_rejected():
    with pytest.raises(PolicyError, match="duplicate rule id"):
        policy("""
default: deny
rules:
  - id: r
    tools: [a]
  - id: r
    tools: [b]
""")


def test_a_rule_with_no_tools_is_rejected():
    with pytest.raises(PolicyError, match="no tools listed"):
        policy("default: deny\nrules:\n  - id: r\n    roles: [user]\n")


def test_an_unknown_effect_is_rejected():
    with pytest.raises(PolicyError, match="effect must be"):
        policy("default: deny\nrules:\n  - id: r\n    tools: [a]\n    effect: maybe\n")


def test_an_empty_constraint_is_rejected():
    """`path: {}` reads as a constraint and constrains nothing."""
    with pytest.raises(PolicyError, match="non-empty mapping"):
        policy("""
default: deny
rules:
  - id: r
    tools: [a]
    arguments:
      path: {}
""")


def test_malformed_yaml_raises_rather_than_producing_an_empty_policy():
    """An unparsed policy must never be treated as 'no rules', which in a
    deny-by-default engine looks like a working lockdown and in an
    allow-by-default one is a breach."""
    with pytest.raises(PolicyError, match="not valid YAML"):
        policy("rules: [\n  - id: unclosed\n")


def test_an_empty_file_is_an_error():
    with pytest.raises(PolicyError, match="empty"):
        policy("")


def test_every_operator_is_covered_by_a_test():
    """A new operator without a test is a new way to be wrong."""
    tested = {
        "equals", "not_equals", "one_of", "starts_with",
        "matches", "glob", "under_path", "not_under_path",
    }
    assert set(OPERATORS) == tested, (
        f"operators without tests: {set(OPERATORS) - tested}"
    )


@pytest.mark.parametrize("op,expected,actual,result", [
    ("equals", "x", "x", True),
    ("equals", "x", "y", False),
    ("not_equals", "x", "y", True),
    ("one_of", ["a", "b"], "a", True),
    ("one_of", ["a", "b"], "c", False),
    ("starts_with", "/home/", "/home/alice", True),
    ("starts_with", "/home/", "/etc", False),
    ("glob", "*.txt", "notes.txt", True),
    ("glob", "*.txt", "notes.exe", False),
    ("under_path", "/home/alice", "/home/alice/x", True),
    ("under_path", "/home/alice", "/home/bob/x", False),
    ("not_under_path", "/home", "/etc/shadow", True),
    ("not_under_path", "/home", "/home/alice/x", False),
])
def test_operator_behaviour(op, expected, actual, result):
    assert OPERATORS[op](actual, expected) is result


def test_one_of_rejects_a_non_list():
    with pytest.raises(PolicyError, match="one_of expects a list"):
        OPERATORS["one_of"]("a", "not-a-list")


# --- hardening found by reading the reference implementation -----------------
#
# The official MCP filesystem server's path-validation.ts rejects null bytes
# before normalising. under_path did not, until that was noticed. A path
# containing one can be truncated by a downstream consumer that hands it to a
# C API, so the string this function judged is not the string that gets opened.


def test_a_null_byte_in_the_path_is_refused():
    p = policy("""
default: deny
rules:
  - id: r
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: /home/alice }
""")
    assert p.evaluate(call(arguments={"path": "/home/alice/ok.txt"})).allowed
    assert not p.evaluate(call(arguments={"path": "/home/alice/ok.txt\x00/../../etc/shadow"})).allowed


def test_a_null_byte_in_the_allowed_prefix_is_refused_too():
    assert OPERATORS["under_path"]("/home/alice/x", "/home/alice\x00") is False


def test_not_under_path_also_refuses_null_bytes():
    """It must not invert into an accidental allow.

    not_under_path is used for deny rules, so returning True for a malformed
    path would be correct here, but only by accident. The important property
    is that under_path refuses it, which makes the deny fire.
    """
    assert OPERATORS["not_under_path"]("/home/alice/x\x00", "/home") is True
