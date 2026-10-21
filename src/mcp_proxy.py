"""An authorizing proxy for MCP.

Sits between an MCP client and an MCP server. Every ``tools/call`` is
evaluated against the policy before it is forwarded, and a denied call is
answered with a JSON-RPC error instead of reaching the server.

Why this layer exists
---------------------
MCP's own authorization specification is explicit about its scope: it
"provides authorization capabilities at the transport level, enabling MCP
clients to make requests to restricted MCP servers on behalf of resource
owners." That answers *may this client connect to this server*. It does not
answer *may this principal invoke this tool with these arguments*, and the
second question is the one that decides whether one user can read another's
data.

Two further gaps follow from the spec as written:

  - Authorization is OPTIONAL, so a server may implement none of it.
  - STDIO transports are told explicitly not to follow it, and instead to take
    credentials from the environment. Most locally-run MCP servers are STDIO,
    which means the only identity in play is the operating system user who
    started the process, shared by every caller of the agent.

So a proxy has to supply the principal. It comes from the session the proxy is
serving, never from the request: a client that can state who it is, is a
client that can state it is somebody else.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .gate import Gate
from .normalize import Principal, from_mcp
from .policy import Policy

# JSON-RPC reserves -32768..-32000 for protocol errors; -32000 and below are
# available for application use. A distinct code matters because a client
# needs to tell "you may not do that" from "that tool does not exist", and
# answering both with -32601 trains agents to retry a refusal as if it were a
# typo.
AUTHORIZATION_DENIED = -32040


class MCPAuthzProxy:
    """Wraps an upstream MCP server with per-call authorization.

    ``forward`` is whatever delivers a JSON-RPC request to the upstream server
    and returns its response: a stdio pipe, an HTTP client, or an in-process
    handler. The proxy is transport agnostic on purpose, because the
    authorization decision is.
    """

    def __init__(
        self,
        policy: Policy,
        forward: Callable[[dict], dict],
        *,
        hide_unavailable_tools: bool = True,
    ):
        self.policy = policy
        self._forward = forward
        self.hide_unavailable_tools = hide_unavailable_tools
        self.gate = Gate(policy, lambda call: None)

    # -- the interesting method ------------------------------------------

    def handle(self, request: dict, principal: Principal) -> dict:
        """Handle one JSON-RPC request on behalf of ``principal``."""
        method = request.get("method")

        if method == "tools/call":
            return self._handle_tools_call(request, principal)
        if method == "tools/list" and self.hide_unavailable_tools:
            return self._handle_tools_list(request, principal)

        # Everything else is protocol plumbing: initialize, ping, resources,
        # prompts. Forwarded untouched. A proxy that reinterprets methods it
        # does not understand is a proxy that breaks on the next spec version.
        return self._forward(request)

    def _handle_tools_call(self, request: dict, principal: Principal) -> dict:
        try:
            call = from_mcp(request, principal)
        except ValueError as exc:
            return self._error(request, AUTHORIZATION_DENIED, f"malformed tools/call: {exc}")

        decision = self.gate.check(call)
        if not decision.allowed:
            # The message is deliberately uninformative about *why*. A client
            # that learns which argument offended can map the policy by
            # probing, one call at a time.
            return self._error(
                request,
                AUTHORIZATION_DENIED,
                f"Tool call '{call.tool}' is not permitted for this principal.",
            )

        return self._forward(request)

    def _handle_tools_list(self, request: dict, principal: Principal) -> dict:
        """Drop tools the principal could never successfully call.

        Defence in depth, not a control. A tool the model never sees is a tool
        it cannot be talked into calling, which removes a whole class of
        injection from the board cheaply. But the gate still evaluates every
        call, because hiding a tool is not the same as refusing it and a
        client is free to call a name it was never shown.

        The test is whether *any* call to the tool could be allowed, not
        whether a particular one would be. A tool is listed if the principal
        could use it at all; the arguments are judged at call time.
        """
        response = self._forward(request)
        tools = (response.get("result") or {}).get("tools")
        if not isinstance(tools, list):
            return response

        visible = [t for t in tools if self._could_ever_call(t.get("name", ""), principal)]
        response = {**response, "result": {**response["result"], "tools": visible}}
        return response

    def _could_ever_call(self, tool_name: str, principal: Principal) -> bool:
        """Is there any allow rule this principal could satisfy for this tool?

        Argument constraints are not evaluated here, only tool name and roles.
        Deciding visibility on arguments would require inventing arguments,
        and a tool hidden because one call would fail is a tool the user
        cannot discover for the calls that would succeed.
        """
        for rule in self.policy.rules:
            if rule.effect != "allow":
                continue
            if rule.matches_tool(tool_name) and rule.matches_roles(principal):
                return True
        return False

    @staticmethod
    def _error(request: dict, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {"code": code, "message": message},
        }

    # -- reporting -------------------------------------------------------

    @property
    def audit(self) -> list[Any]:
        return self.gate.audit

    def summary(self) -> dict[str, int]:
        return self.gate.summary()
