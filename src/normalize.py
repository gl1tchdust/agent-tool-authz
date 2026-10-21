"""One shape for a tool call, whatever produced it.

Every agent framework has invented its own envelope for the same three facts:
which tool, which arguments, on whose behalf. LangChain calls it an
``AgentAction``, the Anthropic API calls it a ``tool_use`` block, MCP calls it
a ``tools/call`` request. They differ in spelling and in nothing else that
matters to an authorization decision.

Normalising first is what keeps the policy engine from growing a branch per
framework. A gate that knows about LangChain is a gate that breaks when
LangChain changes; a gate that knows about tool calls does not.

The third fact is the one frameworks keep leaving out. A tool call arrives
with a tool name and arguments, and nothing about *who is asking*. That is
supplied by the caller of this module, from the session, and it is the whole
reason an authorization decision is possible at all.
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class Principal:
    """Who the agent is acting for.

    Not the agent, and not the model. The human or service whose authority the
    agent is borrowing. An agent has no authority of its own, which is the
    point most agent frameworks miss: they authenticate the *application* to
    the tool server once, at startup, and then every user of that application
    shares one set of permissions.
    """

    id: str
    roles: frozenset[str] = frozenset()
    # Free-form claims the policy can match on: tenant, org, plan, anything.
    attributes: dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("a principal must have an id; use Principal.anonymous() instead")
        if not isinstance(self.roles, frozenset):
            object.__setattr__(self, "roles", frozenset(self.roles))

    @classmethod
    def anonymous(cls) -> Principal:
        return cls(id="<anonymous>", roles=frozenset())

    @property
    def is_anonymous(self) -> bool:
        return self.id == "<anonymous>"


@dataclasses.dataclass(frozen=True)
class ToolCall:
    """A single tool invocation, normalised.

    ``source`` records which envelope it came out of. It is carried for
    debugging and for the audit trail, never for policy decisions: a policy
    that behaves differently depending on the framework is a policy with a
    bypass.
    """

    tool: str
    arguments: dict[str, Any]
    principal: Principal
    call_id: str | None = None
    source: str = "generic"

    def argument(self, name: str, default: Any = None) -> Any:
        return self.arguments.get(name, default)


def from_anthropic(block: Any, principal: Principal) -> ToolCall:
    """Normalise a ``tool_use`` content block from the Anthropic Messages API.

    Accepts the SDK object or the plain dict the raw API returns, because the
    two are not interchangeable and callers have both.
    """
    get = (lambda k: block.get(k)) if isinstance(block, dict) else (lambda k: getattr(block, k, None))
    name = get("name")
    if not name:
        raise ValueError(f"not a tool_use block: {block!r}")
    return ToolCall(
        tool=name,
        arguments=dict(get("input") or {}),
        principal=principal,
        call_id=get("id"),
        source="anthropic",
    )


def from_mcp(request: dict, principal: Principal) -> ToolCall:
    """Normalise an MCP ``tools/call`` JSON-RPC request.

    MCP's own authorization is transport level: it establishes that a client
    may talk to a server on a resource owner's behalf. It does not carry a
    principal down to the individual call, so one is supplied here from the
    session the proxy is serving.
    """
    if request.get("method") != "tools/call":
        raise ValueError(f"not a tools/call request: {request.get('method')!r}")
    params = request.get("params") or {}
    name = params.get("name")
    if not name:
        raise ValueError("tools/call request has no params.name")
    return ToolCall(
        tool=name,
        arguments=dict(params.get("arguments") or {}),
        principal=principal,
        call_id=str(request.get("id")) if request.get("id") is not None else None,
        source="mcp",
    )


def from_openai(call: Any, principal: Principal) -> ToolCall:
    """Normalise an OpenAI-style ``tool_calls`` entry.

    The arguments arrive as a JSON *string* rather than an object, which is a
    small difference with a sharp edge: a malformed string here must not be
    silently treated as an empty argument set, because an empty argument set
    sails through any policy that matches on argument values.
    """
    import json

    get = (lambda k: call.get(k)) if isinstance(call, dict) else (lambda k: getattr(call, k, None))
    function = get("function") or {}
    fget = (lambda k: function.get(k)) if isinstance(function, dict) else (lambda k: getattr(function, k, None))

    name = fget("name")
    if not name:
        raise ValueError(f"not a tool call: {call!r}")

    raw = fget("arguments")
    if isinstance(raw, str):
        try:
            arguments = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as exc:
            raise ValueError(f"tool call {name!r} has unparseable arguments: {exc}") from exc
    else:
        arguments = dict(raw or {})

    if not isinstance(arguments, dict):
        raise ValueError(f"tool call {name!r} arguments are not an object: {type(arguments).__name__}")

    return ToolCall(
        tool=name,
        arguments=arguments,
        principal=principal,
        call_id=get("id"),
        source="openai",
    )
