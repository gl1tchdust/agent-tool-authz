"""Policy model for tool calls.

Deny by default. Every rule is an explicit grant, an explicit denial wins over
any grant, and anything the policy does not mention is refused.

The part that matters is that rules constrain **arguments**, not just tool
names. "May this principal call `read_file`" is a function-level question and
answering only that is how agents end up reading each other's data: every user
of the application shares one grant. "May this principal call `read_file` with
*this path*" is the object-level question, and it is the one that stops the
attack.

Principal interpolation is what makes that expressible without a rule per
user. A constraint of ``/home/{principal.id}/`` is one rule that means "your
own files", for everyone.

Failure modes this is built to avoid:

  - A typo in an operator name silently widening access. Unknown operators
    raise at load time, and an unparsed policy is never treated as an empty
    one.
  - A rule matching when an argument is absent. A constraint on an argument
    the call did not supply does not match, rather than vacuously passing.
  - A deny being overridden by a later allow. Denies are evaluated first and
    are final.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import pathlib
import re
from typing import Any

import yaml

from .normalize import Principal, ToolCall


class PolicyError(Exception):
    """The policy itself is wrong. Never used to report a denied call."""


@dataclasses.dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: str | None
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


# --- argument constraints ----------------------------------------------------
#
# Each operator answers: does this actual argument value satisfy this
# constraint? Interpolation of {principal.*} has already happened by the time
# these run.

def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _op_equals(actual: Any, expected: Any) -> bool:
    return actual == expected


def _op_not_equals(actual: Any, expected: Any) -> bool:
    return actual != expected


def _op_one_of(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, (list, tuple, set)):
        raise PolicyError(f"one_of expects a list, got {type(expected).__name__}")
    return actual in expected


def _op_starts_with(actual: Any, expected: Any) -> bool:
    return _as_text(actual).startswith(_as_text(expected))


def _op_matches(actual: Any, expected: Any) -> bool:
    # Fullmatch, not search. A policy author writing `matches: user-\d+`
    # means the whole value, and `search` would accept
    # `../../etc/passwd#user-1`.
    return re.fullmatch(_as_text(expected), _as_text(actual)) is not None


def _op_glob(actual: Any, expected: Any) -> bool:
    return fnmatch.fnmatchcase(_as_text(actual), _as_text(expected))


def _op_under_path(actual: Any, expected: Any) -> bool:
    """Containment by resolved path, not by string prefix.

    `starts_with` is the obvious way to express "inside this directory" and it
    is wrong: `/home/alice/../bob/secret` starts with `/home/alice/`. Resolving
    first is what closes the traversal.
    """
    base_text, target_text = _as_text(expected), _as_text(actual)

    # Null bytes are rejected before anything else. A path containing one can
    # be truncated by a downstream consumer that hands it to a C API, so the
    # string this function judged and the string that gets opened are not the
    # same string. The reference MCP filesystem server rejects them in its own
    # path validation for the same reason; this was missing here until reading
    # that implementation.
    if "\x00" in base_text or "\x00" in target_text:
        return False

    try:
        base = pathlib.PurePosixPath(base_text)
        target = pathlib.PurePosixPath(target_text)
    except (TypeError, ValueError):
        return False

    # Normalise .. and . without touching the filesystem, which may not have
    # these paths and must not be consulted for an authorization decision.
    def normalise(p: pathlib.PurePosixPath) -> list[str]:
        parts: list[str] = []
        for part in p.parts:
            if part == "..":
                if parts and parts[-1] not in ("/", ""):
                    parts.pop()
                else:
                    # Escaping above the root: never inside anything.
                    return ["\x00escaped"]
            elif part not in (".",):
                parts.append(part)
        return parts

    base_parts = normalise(base)
    target_parts = normalise(target)
    if base_parts == ["\x00escaped"] or target_parts == ["\x00escaped"]:
        return False
    return target_parts[: len(base_parts)] == base_parts


def _op_not_under_path(actual: Any, expected: Any) -> bool:
    """The negation of under_path.

    Needed for the common "deny anything outside X" rule. Expressing that as
    `not_equals: ""` is the mistake this exists to prevent: it reads like a
    guard and matches every non-empty path, so it denies the legitimate
    traffic too. The attack suite scored a perfect block rate against a policy
    written that way, because every attack was blocked and so was everything
    else.
    """
    return not _op_under_path(actual, expected)


OPERATORS = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "one_of": _op_one_of,
    "starts_with": _op_starts_with,
    "matches": _op_matches,
    "glob": _op_glob,
    "under_path": _op_under_path,
    "not_under_path": _op_not_under_path,
}


def interpolate(value: Any, principal: Principal) -> Any:
    """Substitute {principal.id} and {principal.attributes.x} into a constraint.

    Only principal fields. Deliberately not the call's own arguments: a
    constraint that interpolated an argument could be made to match itself,
    which is a policy that always passes.
    """
    if isinstance(value, list):
        return [interpolate(v, principal) for v in value]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        path = match.group(1).split(".")
        if path[0] != "principal":
            raise PolicyError(f"only principal.* may be interpolated, got {{{match.group(1)}}}")
        if path[1:] == ["id"]:
            return principal.id
        if len(path) >= 3 and path[1] == "attributes":
            found = principal.attributes
            for key in path[2:]:
                if not isinstance(found, dict) or key not in found:
                    raise PolicyError(
                        f"principal {principal.id!r} has no attribute {'.'.join(path[2:])!r}"
                    )
                found = found[key]
            return _as_text(found)
        raise PolicyError(f"unknown interpolation {{{match.group(1)}}}")

    return re.sub(r"\{([a-zA-Z0-9_.]+)\}", replace, value)


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    effect: str                      # "allow" | "deny"
    tools: tuple[str, ...]           # exact names or globs
    roles: tuple[str, ...] = ()      # empty means any role, including none
    arguments: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    description: str = ""

    def matches_tool(self, name: str) -> bool:
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in self.tools)

    def matches_roles(self, principal: Principal) -> bool:
        if not self.roles:
            return True
        return bool(principal.roles & set(self.roles))

    def matches_arguments(self, call: ToolCall) -> bool:
        for arg_name, constraint in self.arguments.items():
            if arg_name not in call.arguments:
                # A constraint on an argument that was not supplied does not
                # match. Treating it as satisfied would let a call slip the
                # constraint by simply omitting the field.
                return False
            actual = call.arguments[arg_name]
            for op_name, expected in constraint.items():
                op = OPERATORS[op_name]           # validated at load time
                if not op(actual, interpolate(expected, call.principal)):
                    return False
        return True

    def matches(self, call: ToolCall) -> bool:
        return (
            self.matches_tool(call.tool)
            and self.matches_roles(call.principal)
            and self.matches_arguments(call)
        )


@dataclasses.dataclass
class Policy:
    rules: list[Rule]
    version: int = 1

    @classmethod
    def from_dict(cls, doc: dict) -> Policy:
        if not isinstance(doc, dict):
            raise PolicyError("policy must be a mapping")

        default = doc.get("default", "deny")
        if default != "deny":
            # There is no allow-by-default mode. A gate whose default is allow
            # is not a gate, and offering the option invites someone to reach
            # for it the first time a policy is inconvenient.
            raise PolicyError("default must be 'deny'; allow-by-default is not supported")

        rules = []
        seen_ids = set()
        for index, raw in enumerate(doc.get("rules") or []):
            rule_id = raw.get("id") or f"rule[{index}]"
            if rule_id in seen_ids:
                raise PolicyError(f"duplicate rule id {rule_id!r}")
            seen_ids.add(rule_id)

            effect = raw.get("effect", "allow")
            if effect not in ("allow", "deny"):
                raise PolicyError(f"rule {rule_id!r}: effect must be allow or deny, got {effect!r}")

            tools = raw.get("tools")
            if isinstance(tools, str):
                tools = [tools]
            if not tools:
                raise PolicyError(f"rule {rule_id!r}: no tools listed")

            arguments = raw.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise PolicyError(f"rule {rule_id!r}: arguments must be a mapping")
            for arg_name, constraint in arguments.items():
                if not isinstance(constraint, dict) or not constraint:
                    raise PolicyError(
                        f"rule {rule_id!r}: constraint on {arg_name!r} must be a non-empty mapping"
                    )
                for op_name in constraint:
                    if op_name not in OPERATORS:
                        # Fail closed and loudly. A mistyped operator that was
                        # ignored would silently drop a constraint and widen
                        # the rule, which is the worst possible outcome.
                        raise PolicyError(
                            f"rule {rule_id!r}: unknown operator {op_name!r} on {arg_name!r}. "
                            f"Known: {', '.join(sorted(OPERATORS))}"
                        )

            roles = raw.get("roles") or ()
            if isinstance(roles, str):
                roles = [roles]

            rules.append(Rule(
                id=rule_id,
                effect=effect,
                tools=tuple(tools),
                roles=tuple(roles),
                arguments=arguments,
                description=raw.get("description", ""),
            ))

        return cls(rules=rules, version=int(doc.get("version", 1)))

    @classmethod
    def from_yaml(cls, text: str) -> Policy:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy is not valid YAML: {exc}") from exc
        if doc is None:
            raise PolicyError("policy is empty")
        return cls.from_dict(doc)

    @classmethod
    def from_file(cls, path: str | pathlib.Path) -> Policy:
        return cls.from_yaml(pathlib.Path(path).read_text(encoding="utf-8"))

    def evaluate(self, call: ToolCall) -> Decision:
        """Decide one call.

        Denies first and final, then allows, then the default. Evaluating
        allows first and letting a later deny override would make the result
        depend on rule order, which is how policies acquire bypasses nobody
        can see by reading them.
        """
        for rule in self.rules:
            if rule.effect == "deny" and rule.matches(call):
                return Decision(
                    allowed=False,
                    rule_id=rule.id,
                    reason=rule.description or f"denied by rule {rule.id!r}",
                )

        for rule in self.rules:
            if rule.effect == "allow" and rule.matches(call):
                return Decision(
                    allowed=True,
                    rule_id=rule.id,
                    reason=rule.description or f"allowed by rule {rule.id!r}",
                )

        return Decision(
            allowed=False,
            rule_id=None,
            reason=(
                f"no rule grants {call.principal.id!r} the call "
                f"{call.tool}({', '.join(sorted(call.arguments))}); default is deny"
            ),
        )
