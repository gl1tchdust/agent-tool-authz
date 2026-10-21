"""Tests for the MCP authorizing proxy.

The proxy's job is that a denied tools/call never reaches the upstream server.
Everything else is plumbing that must not break the protocol.
"""

from __future__ import annotations

from src.mcp_proxy import AUTHORIZATION_DENIED, MCPAuthzProxy
from src.normalize import Principal
from src.policy import Policy

ALICE = Principal(id="alice", roles=frozenset({"user"}))
ROOT = Principal(id="root", roles=frozenset({"admin", "user"}))
ANON = Principal.anonymous()

POLICY = Policy.from_yaml("""
default: deny
rules:
  - id: own-files
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: "/home/{principal.id}" }
  - id: admin-tools
    tools: [grant_role]
    roles: [admin]
""")


def upstream():
    """A fake MCP server that records what reached it."""
    seen = []

    def forward(request):
        seen.append(request)
        if request.get("method") == "tools/list":
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": [
                {"name": "read_file", "description": "read"},
                {"name": "grant_role", "description": "grant"},
                {"name": "execute_shell", "description": "shell"},
            ]}}
        return {"jsonrpc": "2.0", "id": request.get("id"),
                "result": {"content": [{"type": "text", "text": "ok"}]}}

    return forward, seen


def tools_call(name, arguments, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


# --- the only thing that really matters --------------------------------------


def test_a_denied_call_never_reaches_the_upstream_server():
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)

    response = proxy.handle(tools_call("read_file", {"path": "/home/bob/secret"}), ALICE)

    assert seen == [], "the upstream server must not have been contacted"
    assert response["error"]["code"] == AUTHORIZATION_DENIED


def test_an_allowed_call_is_forwarded_unchanged():
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    request = tools_call("read_file", {"path": "/home/alice/notes"})

    response = proxy.handle(request, ALICE)

    assert seen == [request], "forwarded verbatim"
    assert "error" not in response


def test_the_error_preserves_the_request_id():
    """A client correlating responses by id hangs forever otherwise."""
    forward, _ = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    response = proxy.handle(tools_call("read_file", {"path": "/etc/shadow"}, request_id="abc"), ALICE)
    assert response["id"] == "abc"
    assert response["jsonrpc"] == "2.0"


def test_the_error_message_does_not_leak_the_policy():
    """A client that learns which argument offended can map the policy."""
    forward, _ = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    message = proxy.handle(tools_call("read_file", {"path": "/home/bob/x"}), ALICE)["error"]["message"]
    assert "bob" not in message
    assert "own-files" not in message
    assert "path" not in message.lower()


def test_denial_uses_a_distinct_code_from_method_not_found():
    """Answering both with -32601 trains agents to retry a refusal."""
    assert AUTHORIZATION_DENIED != -32601
    assert AUTHORIZATION_DENIED <= -32000


def test_an_unknown_tool_is_denied_by_default_not_forwarded():
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    proxy.handle(tools_call("execute_shell", {"command": "rm -rf /"}), ALICE)
    assert seen == []


def test_a_malformed_tools_call_is_refused_rather_than_forwarded():
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    response = proxy.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}, ALICE)
    assert seen == []
    assert "malformed" in response["error"]["message"]


def test_anonymous_callers_are_denied():
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    proxy.handle(tools_call("read_file", {"path": "/home/alice/x"}), ANON)
    assert seen == []


# --- protocol plumbing must keep working -------------------------------------


def test_non_tool_methods_are_forwarded_untouched():
    """A proxy that reinterprets methods it does not know breaks on the next
    spec version."""
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    for method in ("initialize", "ping", "resources/list", "prompts/get"):
        request = {"jsonrpc": "2.0", "id": 1, "method": method}
        proxy.handle(request, ALICE)
    assert [r["method"] for r in seen] == ["initialize", "ping", "resources/list", "prompts/get"]


# --- tool list filtering: defence in depth, not a control --------------------


def test_tools_list_hides_tools_the_principal_can_never_call():
    forward, _ = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    response = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ALICE)
    names = [t["name"] for t in response["result"]["tools"]]
    assert names == ["read_file"], "grant_role is admin-only, execute_shell is ungranted"


def test_an_admin_sees_the_admin_tools():
    forward, _ = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    response = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ROOT)
    assert sorted(t["name"] for t in response["result"]["tools"]) == ["grant_role", "read_file"]


def test_hiding_a_tool_is_not_the_same_as_refusing_it():
    """The decisive test. A client may call a name it was never shown, so the
    gate must still refuse it."""
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)

    listed = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ALICE)
    assert "grant_role" not in [t["name"] for t in listed["result"]["tools"]]

    seen.clear()
    response = proxy.handle(tools_call("grant_role", {"user": "alice", "role": "admin"}), ALICE)
    assert seen == [], "hidden and still enforced"
    assert response["error"]["code"] == AUTHORIZATION_DENIED


def test_filtering_can_be_turned_off_without_affecting_enforcement():
    forward, seen = upstream()
    proxy = MCPAuthzProxy(POLICY, forward, hide_unavailable_tools=False)

    listed = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ALICE)
    assert len(listed["result"]["tools"]) == 3, "nothing hidden"

    seen.clear()
    proxy.handle(tools_call("grant_role", {"user": "alice", "role": "admin"}), ALICE)
    assert seen == [], "still refused"


def test_a_tools_list_response_without_a_tools_array_is_passed_through():
    """An upstream error response must not be mangled by the filter."""
    def forward(request):
        return {"jsonrpc": "2.0", "id": request["id"],
                "error": {"code": -32603, "message": "upstream exploded"}}

    proxy = MCPAuthzProxy(POLICY, forward)
    response = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ALICE)
    assert response["error"]["message"] == "upstream exploded"


# --- audit -------------------------------------------------------------------


def test_every_decision_is_audited():
    forward, _ = upstream()
    proxy = MCPAuthzProxy(POLICY, forward)
    proxy.handle(tools_call("read_file", {"path": "/home/alice/a"}), ALICE)
    proxy.handle(tools_call("read_file", {"path": "/home/bob/b"}), ALICE)
    assert proxy.summary() == {"total": 2, "allowed": 1, "denied": 1}
