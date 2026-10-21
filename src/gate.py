"""The enforcement point.

Sits between the model and the tools. Every tool call is evaluated against the
policy before it executes, and a denied call never reaches the tool.

The design assumption, which is the whole argument of this repository:

    The model is an untrusted caller.

Not malicious, and not broken. Untrusted in the ordinary security sense: its
output is influenced by data it read, some of which an attacker wrote, so what
it asks for cannot be the basis of the decision to allow it. This is the same
reason an API does not authorize a request by reading a field in the request
body.

That has a consequence worth stating plainly. The gate deliberately does not
try to work out whether a call is the result of prompt injection. It cannot,
and tools that claim to are measuring the wrong thing. A call to
``send_email(to=attacker)`` is identical whether the user asked for it or a
poisoned web page did. The decidable question is whether this principal is
permitted to send mail to that address at all, and that question has an answer
that does not depend on guessing the model's state.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Callable
from typing import Any

from .normalize import Principal, ToolCall
from .policy import Decision, Policy


@dataclasses.dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    principal_id: str
    tool: str
    arguments: dict[str, Any]
    allowed: bool
    rule_id: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class ToolDenied(Exception):
    """Raised only when a caller asked for strict mode."""

    def __init__(self, call: ToolCall, decision: Decision):
        super().__init__(f"{call.tool} denied for {call.principal.id}: {decision.reason}")
        self.call = call
        self.decision = decision


# How a denial is reported back to the model. Phrasing matters more than it
# looks: the model is about to read this and decide what to do next. It should
# learn that the action is not available, without being told anything it could
# use to probe the policy. "Denied by rule read-own-files on argument path" is
# an oracle; this is not.
DENIAL_MESSAGE = (
    "This action was refused by policy and was not performed. "
    "Do not retry it or attempt a variation. "
    "Tell the user the action is not permitted for their account."
)


class Gate:
    """Wraps a tool executor with an authorization decision.

    ``execute`` is whatever actually runs a tool: a dict of callables, an MCP
    client, a framework's executor. The gate does not care, and never calls it
    for a denied call.
    """

    def __init__(
        self,
        policy: Policy,
        execute: Callable[[ToolCall], Any],
        *,
        strict: bool = False,
        on_decision: Callable[[AuditEntry], None] | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ):
        self.policy = policy
        self._execute = execute
        self.strict = strict
        self._on_decision = on_decision
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.audit: list[AuditEntry] = []

    def check(self, call: ToolCall) -> Decision:
        """Evaluate without executing. Used by the attack harness to measure."""
        decision = self.policy.evaluate(call)
        entry = AuditEntry(
            timestamp=self._clock().isoformat(),
            principal_id=call.principal.id,
            tool=call.tool,
            arguments=call.arguments,
            allowed=decision.allowed,
            rule_id=decision.rule_id,
            reason=decision.reason,
        )
        self.audit.append(entry)
        if self._on_decision:
            self._on_decision(entry)
        return decision

    def call(self, call: ToolCall) -> Any:
        """Evaluate, then execute only if allowed.

        A denial returns a message rather than raising, by default. An agent
        loop that crashes on the first denied call is one a user will route
        around, and a gate people route around protects nothing. Strict mode
        exists for batch contexts where a denial should stop the run.
        """
        decision = self.check(call)
        if not decision.allowed:
            if self.strict:
                raise ToolDenied(call, decision)
            return DENIAL_MESSAGE
        return self._execute(call)

    # -- reporting -------------------------------------------------------

    @property
    def denied(self) -> list[AuditEntry]:
        return [e for e in self.audit if not e.allowed]

    @property
    def allowed(self) -> list[AuditEntry]:
        return [e for e in self.audit if e.allowed]

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.audit),
            "allowed": len(self.allowed),
            "denied": len(self.denied),
        }


def open_gate(execute: Callable[[ToolCall], Any]) -> Gate:
    """A gate that allows everything, for measuring what the gate is worth.

    This is the control arm. "Our gate blocked 14 attacks" means nothing
    without the number of those attacks that would have succeeded without it,
    and the only honest way to get that number is to run the same attacks
    through a policy that permits everything.

    It is a named, obvious function rather than a ``Policy(allow_all=True)``
    flag precisely so it cannot be reached by accident from a config file.
    """
    policy = Policy(rules=[])

    class _OpenPolicy(Policy):
        def evaluate(self, call: ToolCall) -> Decision:  # noqa: D102
            return Decision(allowed=True, rule_id="<no policy>", reason="control arm: no policy enforced")

    return Gate(_OpenPolicy(rules=policy.rules), execute)
