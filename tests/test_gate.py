"""Tests for the enforcement point and the normalisers.

The gate's one job is that a denied call does not reach the tool. Everything
else it does is reporting. So the tests that matter most are the ones that
prove the executor was never invoked.
"""

from __future__ import annotations

import datetime as dt

import pytest

from src.gate import DENIAL_MESSAGE, Gate, ToolDenied, open_gate
from src.normalize import (
    Principal,
    ToolCall,
    from_anthropic,
    from_mcp,
    from_openai,
)
from src.policy import Policy

ALICE = Principal(id="alice", roles=frozenset({"user"}))
BOB = Principal(id="bob", roles=frozenset({"user"}))

POLICY = Policy.from_yaml("""
default: deny
rules:
  - id: own-files
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: "/home/{principal.id}" }
""")


def tracking_executor():
    calls = []

    def execute(call):
        calls.append(call)
        return f"contents of {call.arguments.get('path')}"

    return execute, calls


# --- the only thing that really matters --------------------------------------


def test_a_denied_call_never_reaches_the_tool():
    execute, calls = tracking_executor()
    gate = Gate(POLICY, execute)

    result = gate.call(ToolCall("read_file", {"path": "/home/bob/secret"}, ALICE))

    assert calls == [], "the executor must not have been invoked"
    assert result == DENIAL_MESSAGE


def test_an_allowed_call_reaches_the_tool_and_returns_its_result():
    execute, calls = tracking_executor()
    gate = Gate(POLICY, execute)

    result = gate.call(ToolCall("read_file", {"path": "/home/alice/notes"}, ALICE))

    assert len(calls) == 1
    assert result == "contents of /home/alice/notes"


def test_check_never_executes_even_when_it_allows():
    """The benchmark uses check() against destructive tools."""
    execute, calls = tracking_executor()
    gate = Gate(POLICY, execute)

    decision = gate.check(ToolCall("read_file", {"path": "/home/alice/x"}, ALICE))

    assert decision.allowed
    assert calls == []


# --- how a denial is reported ------------------------------------------------


def test_a_denial_returns_a_message_rather_than_raising_by_default():
    """An agent loop that crashes on the first denied call is one users route
    around, and a gate people route around protects nothing."""
    execute, _ = tracking_executor()
    gate = Gate(POLICY, execute)
    assert gate.call(ToolCall("read_file", {"path": "/etc/shadow"}, ALICE)) == DENIAL_MESSAGE


def test_strict_mode_raises_for_batch_callers():
    execute, calls = tracking_executor()
    gate = Gate(POLICY, execute, strict=True)

    with pytest.raises(ToolDenied) as exc:
        gate.call(ToolCall("read_file", {"path": "/etc/shadow"}, ALICE))

    assert calls == []
    assert exc.value.call.tool == "read_file"
    assert not exc.value.decision.allowed


def test_the_denial_message_is_not_an_oracle():
    """It must not leak which rule fired or which argument offended, or an
    attacker can map the policy by probing."""
    assert "rule" not in DENIAL_MESSAGE.lower()
    assert "path" not in DENIAL_MESSAGE.lower()
    assert "policy" in DENIAL_MESSAGE.lower(), "it should still say why, in general terms"


# --- audit -------------------------------------------------------------------


def test_every_decision_is_audited_including_the_allowed_ones():
    execute, _ = tracking_executor()
    gate = Gate(POLICY, execute)

    gate.call(ToolCall("read_file", {"path": "/home/alice/a"}, ALICE))
    gate.call(ToolCall("read_file", {"path": "/home/bob/b"}, ALICE))

    assert gate.summary() == {"total": 2, "allowed": 1, "denied": 1}
    assert [e.allowed for e in gate.audit] == [True, False]
    assert gate.denied[0].tool == "read_file"
    assert gate.denied[0].principal_id == "alice"


def test_the_audit_entry_records_the_arguments_that_were_judged():
    execute, _ = tracking_executor()
    gate = Gate(POLICY, execute)
    gate.call(ToolCall("read_file", {"path": "/home/bob/x"}, ALICE))
    assert gate.audit[0].arguments == {"path": "/home/bob/x"}


def test_a_decision_hook_fires_for_streaming_to_a_siem():
    seen = []
    execute, _ = tracking_executor()
    gate = Gate(POLICY, execute, on_decision=seen.append)
    gate.call(ToolCall("read_file", {"path": "/home/bob/x"}, ALICE))
    assert len(seen) == 1 and not seen[0].allowed


def test_the_clock_is_injectable_so_audit_entries_are_testable():
    fixed = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    execute, _ = tracking_executor()
    gate = Gate(POLICY, execute, clock=lambda: fixed)
    gate.check(ToolCall("read_file", {"path": "/home/alice/x"}, ALICE))
    assert gate.audit[0].timestamp == fixed.isoformat()


# --- the control arm ---------------------------------------------------------


def test_the_open_gate_allows_everything():
    """It exists to measure what the real gate is worth."""
    execute, calls = tracking_executor()
    gate = open_gate(execute)

    assert gate.check(ToolCall("anything", {"x": 1}, Principal.anonymous())).allowed
    gate.call(ToolCall("execute_shell", {"command": "rm -rf /"}, Principal.anonymous()))
    assert len(calls) == 1, "the control arm really does execute"


# --- normalisers -------------------------------------------------------------


def test_anthropic_tool_use_block_as_dict():
    call = from_anthropic(
        {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "/x"}},
        ALICE,
    )
    assert (call.tool, call.arguments, call.call_id, call.source) == (
        "read_file", {"path": "/x"}, "toolu_1", "anthropic")


def test_anthropic_tool_use_block_as_object():
    class Block:
        type, id, name, input = "tool_use", "toolu_2", "write_file", {"path": "/y"}

    call = from_anthropic(Block(), ALICE)
    assert call.tool == "write_file" and call.call_id == "toolu_2"


def test_a_block_that_is_not_a_tool_use_is_rejected():
    with pytest.raises(ValueError, match="not a tool_use block"):
        from_anthropic({"type": "text", "text": "hello"}, ALICE)


def test_mcp_tools_call_request():
    call = from_mcp({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/x"}},
    }, ALICE)
    assert (call.tool, call.call_id, call.source) == ("read_file", "7", "mcp")


def test_a_non_tools_call_mcp_request_is_rejected():
    with pytest.raises(ValueError, match="not a tools/call"):
        from_mcp({"method": "tools/list", "id": 1}, ALICE)


def test_openai_arguments_arrive_as_a_json_string():
    call = from_openai({
        "id": "call_1",
        "function": {"name": "read_file", "arguments": '{"path": "/x"}'},
    }, ALICE)
    assert call.arguments == {"path": "/x"}


def test_unparseable_openai_arguments_raise_rather_than_becoming_empty():
    """An empty argument set sails through any policy that constrains values."""
    with pytest.raises(ValueError, match="unparseable arguments"):
        from_openai({"id": "c", "function": {"name": "read_file", "arguments": "{broken"}}, ALICE)


def test_openai_arguments_that_are_not_an_object_are_rejected():
    with pytest.raises(ValueError, match="not an object"):
        from_openai({"id": "c", "function": {"name": "read_file", "arguments": "[1,2]"}}, ALICE)


def test_empty_openai_arguments_string_is_an_empty_dict():
    call = from_openai({"id": "c", "function": {"name": "ping", "arguments": ""}}, ALICE)
    assert call.arguments == {}


# --- principals --------------------------------------------------------------


def test_a_principal_must_have_an_id():
    with pytest.raises(ValueError, match="must have an id"):
        Principal(id="")


def test_anonymous_is_explicit_rather_than_an_empty_string():
    anon = Principal.anonymous()
    assert anon.is_anonymous and anon.roles == frozenset()
    assert not ALICE.is_anonymous


def test_roles_are_coerced_to_a_frozenset_so_rules_can_intersect_them():
    p = Principal(id="x", roles={"a", "b"})
    assert isinstance(p.roles, frozenset)
