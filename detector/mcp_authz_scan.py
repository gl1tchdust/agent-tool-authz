#!/usr/bin/env python3
"""Enumerate the authorization surface of a Python MCP server.

    python -m detector.mcp_authz_scan path/to/server --policy-out policy.yml

Answers three questions about every tool a server exposes:

    1. What does it accept?        parameters, and which look like resource
                                   identifiers rather than options
    2. What does it do?            reads, writes, subprocess, network
    3. What does it claim?         the MCP annotations it declares

And then the one that matters: **do 2 and 3 agree?**

Why that question
-----------------
MCP tools declare their own risk profile through annotations
(`readOnlyHint`, `destructiveHint`, `openWorldHint`), and clients use those
declarations to decide what to auto-approve without asking a human. The
specification is explicit that this is a trust problem: clients "MUST consider
tool annotations to be untrusted unless they come from trusted servers"
(MCP 2026-07-28, Server Tools).

That is correct advice with nothing behind it. "Only trust annotations from
servers you trust" pushes the decision to an operator who has no way to check.
A tool annotated `readOnlyHint: true` whose handler writes to disk is a false
statement in a manifest that an agent is using to skip a confirmation prompt,
and it is decidable by reading the code.

What this deliberately does NOT claim
-------------------------------------
That a server is vulnerable. Most MCP servers are single-user local tools
where a caller-supplied path is the entire point and scoping it would break
the product. Flagging those would be manufacturing findings.

So the output is an *inventory with evidence*, not a verdict. It says "this
tool takes a path from the caller and opens it, with no allowlist check" and
leaves "is that acceptable here?" to the person who knows whether the server
is local or exposed. The one place it does assert a defect is the
declared-versus-actual mismatch, because that is a contradiction inside the
server's own manifest and does not depend on deployment.

Analysis only. This reads source; it never imports, executes or connects to
anything it scans.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import pathlib
import sys
from typing import Any

# Parses Python literals only (numbers, strings, tuples, dicts, booleans).
# Aliased on import to make it unmistakable that this is not the builtin that
# runs arbitrary code: `literal_eval` raises on anything that is not a literal,
# which is exactly what is wanted for reading a decorator's arguments.
from ast import literal_eval as parse_literal

# The MCP SDK accepts snake_case; the wire protocol uses camelCase. Both are
# seen in real servers, sometimes in the same repository.
ANNOTATION_ALIASES = {
    "read_only_hint": "readOnlyHint",
    "readonlyhint": "readOnlyHint",
    "readOnlyHint": "readOnlyHint",
    "destructive_hint": "destructiveHint",
    "destructiveHint": "destructiveHint",
    "idempotent_hint": "idempotentHint",
    "idempotentHint": "idempotentHint",
    "open_world_hint": "openWorldHint",
    "openWorldHint": "openWorldHint",
}

# Names of calls that write to the host. Matched on the attribute or function
# name, which is deliberately shallow: the goal is an inventory a human
# reviews, and a missed alias shows up as a tool with no observed behaviour
# rather than as a false clean bill of health.
WRITE_CALLS = {
    "write", "writelines", "write_text", "write_bytes", "writeFile",
    "mkdir", "makedirs", "rmdir", "remove", "unlink", "rmtree",
    "rename", "copytree", "chmod", "chown",
    "truncate", "touch",
}

# Verbs that only mean "write" with the right receiver. `repo.index.commit()`
# creates a commit; `repo.commit(rev)` resolves one and writes nothing.
# `collection.insert()` writes; `list.insert()` does not. Matching the bare
# verb reported the official git server's read-only `show` tool as a
# readOnlyHint violation, which is the kind of confident wrong answer that
# gets a scanner uninstalled.
QUALIFIED_WRITE_CALLS = {
    "index.commit", "index.add", "index.remove", "index.reset",
    "session.commit", "session.add", "session.delete", "session.merge",
    "db.commit", "db.insert", "db.update", "db.delete", "db.drop",
    "cursor.execute", "conn.commit",
    "collection.insert_one", "collection.update_one", "collection.delete_one",
    "table.put_item", "table.delete_item", "bucket.upload_file", "bucket.put_object",
}
# Network calls. Bare HTTP verbs are deliberately absent: `.get()` is the most
# common method name in Python, and matching it reported `token.claims.get("sub")`
# as a network call in the FastMCP auth example. A verb needs its receiver.
NETWORK_CALLS = {
    "urlopen", "urlretrieve", "AsyncClient", "ClientSession",
}
QUALIFIED_NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "httpx.request", "httpx.stream",
    "client.get", "client.post", "client.put", "client.patch", "client.delete",
    "client.request", "client.stream", "client.send",
    "session.get", "session.post", "session.put", "session.delete",
    "session.request", "aiohttp.request", "urllib.urlopen",
    "socket.connect", "sock.connect",
}

# Subprocess. `run` and `call` are absent for the same reason: `asyncio.run`
# and `app.run` are not shell execution.
SUBPROCESS_CALLS = {
    "Popen", "check_call", "check_output", "getoutput", "getstatusoutput",
}
QUALIFIED_SUBPROCESS_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
    "os.system", "os.popen", "os.execv", "os.spawnv",
    "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
    "commands.getoutput", "pty.spawn",
}

# Writes that destroy or overwrite existing state, as opposed to adding to it.
# MCP defines destructiveHint as "may perform destructive updates" versus
# "only additive updates", so a commit is additive and a delete is not. An
# earlier version treated every write as destructive and reported the official
# git server's `commit` tool, whose destructive_hint=False is correct.
DESTRUCTIVE_CALLS = {
    "unlink", "remove", "rmdir", "rmtree", "delete", "drop", "truncate",
    "rename", "chmod", "chown",
}

# Verbs that mean "network" when the receiver is a module that was imported.
# `httpx.get`, `httpx2.get` and `anything_you_imported.get` all qualify;
# `token.claims.get` does not, because `claims` is not an import.
HTTP_VERBS = {
    "get", "post", "put", "patch", "delete", "head", "options",
    "request", "stream", "send", "fetch", "download", "upload",
}

# Parameter names that usually name a thing rather than configure an action.
# Used to flag the authorization surface, not to assert a bug.
IDENTIFIER_HINTS = (
    "path", "file", "dir", "folder", "repo", "url", "uri", "id", "key",
    "name", "query", "table", "bucket", "account", "user", "project",
    "resource", "target", "host", "endpoint", "database", "collection",
)

# Function names that suggest a caller-supplied value was checked before use.
# Presence is evidence of scoping; absence is not evidence of its lack, which
# is why this contributes to the inventory rather than to a verdict.
VALIDATOR_HINTS = (
    "validate", "verify", "check", "assert", "ensure", "authorize", "authorise",
    "allowed", "permitted", "sanitize", "sanitise", "normalize", "normalise",
    "resolve", "canonical", "is_within", "within_allowed", "guard",
)


# How far from the handler a call may be and still be attributed to the tool.
#
# 0 is the handler body, 1 is a helper it calls directly. Beyond that the
# behaviour usually belongs to the helper rather than to the tool: the official
# git server's commit handler reaches a `.git/MERGE_HEAD` cleanup two levels
# down, which is internal plumbing and not a destructive update to anything the
# caller owns. Attributing it reported a correct annotation as a defect.
#
# Deeper calls still appear in the inventory. They just do not get to assert.
ATTRIBUTION_DEPTH = 1


@dataclasses.dataclass
class Behaviour:
    """Observed calls, each with the shortest call distance from the handler."""

    writes: list[str] = dataclasses.field(default_factory=list)
    network: list[str] = dataclasses.field(default_factory=list)
    subprocess: list[str] = dataclasses.field(default_factory=list)
    validators: list[str] = dataclasses.field(default_factory=list)
    # name -> fewest hops from the handler at which it was seen
    depths: dict[str, int] = dataclasses.field(default_factory=dict)

    @property
    def mutates(self) -> bool:
        return bool(self.writes or self.subprocess)

    def near(self, names: list[str]) -> list[str]:
        """Those of `names` seen close enough to attribute to the tool."""
        return [n for n in names if self.depths.get(n, 99) <= ATTRIBUTION_DEPTH]

    @property
    def near_writes(self) -> list[str]:
        return self.near(self.writes)

    @property
    def near_subprocess(self) -> list[str]:
        return self.near(self.subprocess)

    @property
    def near_network(self) -> list[str]:
        return self.near(self.network)


@dataclasses.dataclass
class ToolDef:
    name: str
    function: str
    file: str
    line: int
    parameters: list[str]
    identifier_parameters: list[str]
    declared: dict[str, Any]
    behaviour: Behaviour

    def as_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["behaviour"] = dataclasses.asdict(self.behaviour)
        return d


@dataclasses.dataclass
class Finding:
    tool: str
    file: str
    line: int
    kind: str
    severity: str
    detail: str


def _literal(node: ast.AST) -> Any:
    """Read a literal out of the AST, or None if it is an expression."""
    try:
        return parse_literal(node)
    except (ValueError, SyntaxError, TypeError):
        return None


def _call_name(node: ast.Call) -> str:
    """The bare callee name: `attr` for `obj.attr()`, `id` for `f()`."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _dotted_name(node: ast.Call) -> str:
    """The last two segments of an attribute call: `index.commit`.

    Needed because the receiver is what disambiguates a verb. Returns an
    empty string for a plain function call, which has no receiver to judge.
    """
    func = node.func
    if not isinstance(func, ast.Attribute):
        return ""
    parent = func.value
    if isinstance(parent, ast.Name):
        return f"{parent.id}.{func.attr}"
    if isinstance(parent, ast.Attribute):
        return f"{parent.attr}.{func.attr}"
    return ""


def _is_plain_call(node: ast.Call) -> bool:
    """Is this `helper(...)` rather than `obj.helper(...)`?

    Only plain calls are followed into module-level functions. Resolving
    `repo.commit(...)` against a module function named `commit` is how the
    scanner once followed a read-only git tool into the commit handler and
    inherited its file deletions.
    """
    return isinstance(node.func, ast.Name)


def _is_tool_decorator(dec: ast.AST) -> ast.Call | None:
    """Match @server.tool(...), @mcp.tool(...), @app.tool(...).

    Bare `@server.tool` without parentheses is also matched, since the SDK
    permits it and a tool is still a tool.

    `call_tool` is deliberately NOT matched. On a low-level `Server`,
    `@server.call_tool()` registers the single dispatcher for every tool the
    server exposes, so it is not a tool definition. Matching it invented one
    phantom tool per server, named after the dispatcher, taking `(name,
    arguments)` and carrying the aggregated behaviour of everything the
    dispatcher could reach.

    Across the registry census that was 65 of the 285 tools reported for the
    largest repository alone, and 92 files used the pattern. Because nobody
    annotates a dispatcher, every phantom landed in the unannotated column and
    pushed the measured annotation rate down.

    Excluding it left those servers reporting zero tools, which was a blind
    spot rather than a wrong answer. It is now closed from the other side:
    `_tools_from_list_handler` reads the `@server.list_tools()` manifest,
    where the tools are declared as data. The dispatcher is still not a tool.
    """
    call = dec if isinstance(dec, ast.Call) else None
    target = call.func if call else dec
    if isinstance(target, ast.Attribute) and target.attr == "tool":
        return call or ast.Call(func=target, args=[], keywords=[])
    return None


class ConstantResolver(ast.NodeVisitor):
    """Collects module-level constants so `annotations=READ_ONLY` resolves.

    The official git MCP server assigns its annotations to a named constant and
    reuses it across eight tools. A scanner that only reads inline literals
    reports every one of them as undeclared, which is both wrong and the kind
    of wrongness that makes people stop reading the output.
    """

    def __init__(self) -> None:
        self.constants: dict[str, ast.AST] = {}
        # Module-level functions, needed twice: to follow a one-line handler
        # into the helper that does the real work, and to resolve an
        # annotations factory into the literals it returns.
        self.functions: dict[str, ast.AST] = {}
        # Module-level import names, including aliases. Needed because
        # receiver-qualified matching only works for libraries you thought to
        # list: the FastMCP map example calls `httpx2.get(...)`, and a list
        # naming `httpx` misses it entirely.
        self.imports: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.constants[target.id] = node.value
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.imports.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            self.imports.add(node.module.split(".")[0])
        for alias in node.names:
            self.imports.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.functions[node.name] = node
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.functions[node.name] = node
        self.generic_visit(node)


def _annotations_from_factory(
    call: ast.Call, functions: dict[str, ast.AST]
) -> dict[str, Any] | None:
    """Resolve `annotations=writes(destructive=False, idempotent=True)`.

    The official git MCP server builds its annotations with a factory whose
    body returns `ToolAnnotations(read_only_hint=False, destructive_hint=
    destructive, ...)`, mixing literals with its own parameters. Without this,
    five of its twelve tools report as undeclared, which understates the
    server and makes the scanner look like it cannot read ordinary code.

    Values come from the factory's literals, with its parameter names
    substituted from the call site.
    """
    name = call.func.id if isinstance(call.func, ast.Name) else None
    factory = functions.get(name) if name else None
    if factory is None or not isinstance(factory, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None

    # What the call site passed in, by parameter name.
    supplied = {kw.arg: _literal(kw.value) for kw in call.keywords if kw.arg}
    positional = [a.arg for a in factory.args.args]
    for index, arg in enumerate(call.args):
        if index < len(positional):
            supplied[positional[index]] = _literal(arg)

    for node in ast.walk(factory):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Call):
            continue
        declared: dict[str, Any] = {}
        for kw in node.value.keywords:
            if not kw.arg or kw.arg not in ANNOTATION_ALIASES:
                continue
            key = ANNOTATION_ALIASES[kw.arg]
            if isinstance(kw.value, ast.Name) and kw.value.id in supplied:
                declared[key] = supplied[kw.value.id]
            else:
                declared[key] = _literal(kw.value)
        if declared:
            return declared
    return None


def extract_annotations(
    call: ast.Call,
    constants: dict[str, ast.AST],
    functions: dict[str, ast.AST] | None = None,
) -> dict[str, Any]:
    """Pull declared MCP annotations out of a tool decorator."""
    functions = functions or {}
    node: ast.AST | None = None
    for kw in call.keywords:
        if kw.arg == "annotations":
            node = kw.value
            break
    if node is None:
        return {}

    # annotations=READ_ONLY  ->  follow the constant
    if isinstance(node, ast.Name) and node.id in constants:
        node = constants[node.id]

    declared: dict[str, Any] = {}

    if isinstance(node, ast.Call):
        # annotations=writes(destructive=False)  ->  follow the factory
        from_factory = _annotations_from_factory(node, functions)
        if from_factory is not None:
            return from_factory
        # annotations=ToolAnnotations(read_only_hint=True, ...)
        for kw in node.keywords:
            if kw.arg and kw.arg in ANNOTATION_ALIASES:
                declared[ANNOTATION_ALIASES[kw.arg]] = _literal(kw.value)
    # annotations={"readOnlyHint": True}
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            name = _literal(key) if key else None
            if isinstance(name, str) and name in ANNOTATION_ALIASES:
                declared[ANNOTATION_ALIASES[name]] = _literal(value)

    return declared


MAX_CALL_DEPTH = 3


def observe(
    func: ast.AST,
    functions: dict[str, ast.AST] | None = None,
    imports: set[str] | None = None,
    depth: int = MAX_CALL_DEPTH,
    _seen_functions: frozenset[str] = frozenset(),
) -> Behaviour:
    """What does this handler actually do, including via module-local helpers?

    Following calls matters more than it sounds. Real MCP handlers are often
    one-line delegates:

        def commit(repo_path: str, message: str) -> str:
            return git_commit(open_repo(repo_path), message)

    Looking only at that body sees no writes at all, so a git server with
    add, commit and reset reports `mutate state: 0`. That is not a near-miss,
    it is the opposite of the truth, and an inventory nobody can trust is
    worse than no inventory.

    Bounded at three levels and guarded against recursion. The bound is a real
    limit, not a formality: a write four hops down is missed, and the README
    says so.
    """
    functions = functions or {}
    imports = imports or set()
    seen = Behaviour()

    here = MAX_CALL_DEPTH - depth          # 0 in the handler, 1 one hop in

    def note(field: str, item: str) -> None:
        target = getattr(seen, field)
        if item not in target:
            target.append(item)
        seen.depths[item] = min(seen.depths.get(item, 99), here)

    def merge(other: Behaviour) -> None:
        for field in ("writes", "network", "subprocess", "validators"):
            for item in getattr(other, field):
                target = getattr(seen, field)
                if item not in target:
                    target.append(item)
                # Keep the shortest distance at which anything was seen.
                seen.depths[item] = min(
                    seen.depths.get(item, 99), other.depths.get(item, 99))

    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not name:
            continue
        dotted = _dotted_name(node)
        lowered = name.lower()

        # A bare verb counts only when it is unambiguous on its own; the rest
        # need their receiver.
        if name in WRITE_CALLS:
            note("writes", name)
        elif dotted in QUALIFIED_WRITE_CALLS:
            note("writes", dotted)

        receiver = dotted.split(".")[0] if dotted else ""
        if name in NETWORK_CALLS:
            note("network", name)
        elif dotted in QUALIFIED_NETWORK_CALLS:
            note("network", dotted)
        elif name in HTTP_VERBS and receiver in imports:
            # requests.get, httpx2.get, whatever_you_imported.post
            note("network", dotted)

        if name in SUBPROCESS_CALLS:
            note("subprocess", name)
        elif dotted in QUALIFIED_SUBPROCESS_CALLS:
            note("subprocess", dotted)
        if any(h in lowered for h in VALIDATOR_HINTS):
            note("validators", name)

        # Follow into a module-local helper, plain calls only. `obj.name()` is
        # a method on some object and has nothing to do with a module function
        # that happens to share the name.
        if (depth > 0 and _is_plain_call(node)
                and name in functions and name not in _seen_functions):
            merge(observe(functions[name], functions, imports, depth - 1,
                          _seen_functions | {name}))

    return seen


def tool_name(call: ast.Call, func_name: str) -> str:
    for kw in call.keywords:
        if kw.arg == "name":
            literal = _literal(kw.value)
            if isinstance(literal, str):
                return literal
            # name=GitTools.STATUS.value and friends: keep the expression so a
            # reader can resolve it, rather than silently reporting the
            # function name as if it were the advertised tool name.
            return f"<{ast.unparse(kw.value)}>"
    if call.args:
        literal = _literal(call.args[0])
        if isinstance(literal, str):
            return literal
    return func_name


def _is_list_tools_decorator(dec: ast.AST) -> bool:
    """Match @server.list_tools(), the low-level manifest handler."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    return isinstance(target, ast.Attribute) and target.attr == "list_tools"


def _is_tool_construction(node: ast.AST) -> bool:
    """`Tool(...)`, `types.Tool(...)`, `mcp.types.Tool(...)`.

    The last name has to be exactly `Tool`, so `ToolAnnotations(...)` and
    `ToolResult(...)` do not match.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name == "Tool"


def _listed_tool_calls(value: ast.AST | None, constants: dict[str, ast.AST],
                       functions: dict[str, ast.AST] | None = None,
                       depth: int = 0) -> list[ast.Call]:
    """`Tool(...)` constructions reachable from a `list_tools` return value.

    Classifying all 85 `list_tools` handlers in the registry corpus by their
    return shape gave:

        57  a list literal of Tool(...) calls
        11  a bare name bound to such a list
         9  a call to a local helper that returns one
         6  a list comprehension
         1  a mixed list
         1  an attribute

    The first three are followed, which is 77 of 85. `return get_all_tools()`
    is the third and is worth the hop: all six of its occurrences are in the
    largest repository in the corpus, and they are annotated, so skipping
    them would have biased the rate in the *opposite* direction from the
    TypeScript gap. Spreads and `READ + WRITE` are followed too. Each hop is
    bounded by MAX_CALL_DEPTH, which also stops a cyclic helper.

    A comprehension is deliberately not followed. Its length exists only at
    run time, so a static reader that guessed would be inventing tools. Those
    return nothing and the server reports the tools it writes out literally,
    which undercounts rather than overcounts.
    """
    functions = functions or {}
    if value is None or depth > MAX_CALL_DEPTH:
        return []
    if _is_tool_construction(value):
        return [value]
    if isinstance(value, ast.Name):
        return _listed_tool_calls(constants.get(value.id), constants,
                                  functions, depth + 1)
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        return (_listed_tool_calls(value.left, constants, functions, depth + 1)
                + _listed_tool_calls(value.right, constants, functions, depth + 1))
    if isinstance(value, (ast.List, ast.Tuple)):
        out: list[ast.Call] = []
        for element in value.elts:
            node = element.value if isinstance(element, ast.Starred) else element
            out.extend(_listed_tool_calls(node, constants, functions, depth + 1))
        return out
    # return get_all_tools()  ->  read what the helper returns
    if isinstance(value, ast.Call):
        target = value.func
        name = (target.attr if isinstance(target, ast.Attribute)
                else getattr(target, "id", ""))
        helper = functions.get(name)
        if helper is not None:
            out = []
            for statement in ast.walk(helper):
                if isinstance(statement, ast.Return):
                    out.extend(_listed_tool_calls(statement.value, constants,
                                                  functions, depth + 1))
            return out
    return []


def _tools_from_list_handler(node: ast.AST, path: pathlib.Path,
                             resolver: ConstantResolver) -> list[ToolDef]:
    """Tools a low-level server declares as data rather than as decorators.

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return [types.Tool(name="read_file", annotations=READ_ONLY)]

    This is the other half of the exclusion documented on
    `_is_tool_decorator`. Skipping `@server.call_tool()` was right, because a
    dispatcher is not a tool, but it left these servers reporting zero tools.
    89 `list_tools` handlers sit in the registry corpus, and the measured
    annotation rate was computed without them.

    **No behaviour is attributed, so these tools never produce findings.**
    The implementation lives in the `call_tool` dispatcher, usually behind a
    chain of `if name == ...` branches, and deciding which branch belongs to
    which tool is the kind of semantic inference that scored 0 of 4 on the
    labelled sample. The declaration is read; the code is not. A tool counted
    here therefore contributes to the annotation rate and to nothing else.

    `parameters` stays empty for the same reason: the signature is a JSON
    `inputSchema`, not a Python one, and the policy scaffold is honest listing
    the tool with no parameters rather than guessing at them.

    Duplicate names are dropped by the caller, not here, because the
    duplication is usually across handlers rather than within one. See
    `scan_file`.
    """
    out: list[ToolDef] = []
    for statement in ast.walk(node):
        if not isinstance(statement, ast.Return):
            continue
        for call in _listed_tool_calls(statement.value, resolver.constants,
                                       resolver.functions):
            out.append(ToolDef(
                name=tool_name(call, "<unnamed>"),
                function=getattr(node, "name", "list_tools"),
                file=str(path),
                line=call.lineno,
                parameters=[],
                identifier_parameters=[],
                declared=extract_annotations(call, resolver.constants,
                                             resolver.functions),
                behaviour=Behaviour(),
            ))
    return out


def scan_file(path: pathlib.Path) -> list[ToolDef]:
    try:
        source = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    resolver = ConstantResolver()
    resolver.visit(tree)

    tools: list[ToolDef] = []
    listed: list[ToolDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_is_list_tools_decorator(d) for d in node.decorator_list):
            listed.extend(_tools_from_list_handler(node, path, resolver))
            continue
        for dec in node.decorator_list:
            call = _is_tool_decorator(dec)
            if call is None:
                continue

            params = [a.arg for a in node.args.args + node.args.kwonlyargs
                      if a.arg not in ("self", "cls", "ctx", "context")]
            identifiers = [p for p in params
                           if any(h in p.lower() for h in IDENTIFIER_HINTS)]

            tools.append(ToolDef(
                name=tool_name(call, node.name),
                function=node.name,
                file=str(path),
                line=node.lineno,
                parameters=params,
                identifier_parameters=identifiers,
                declared=extract_annotations(call, resolver.constants, resolver.functions),
                behaviour=observe(node, resolver.functions, resolver.imports),
            ))
            break

    # One manifest per name. A server that offers both stdio and HTTP
    # transports declares `@app.list_tools()` once per transport, each
    # returning the same manifest, and the msteams server in the registry
    # corpus did exactly that: 22 tools reported for 11 real ones. A
    # branching return inside one handler duplicates the same way.
    #
    # A decorator-defined tool wins over a listed one of the same name,
    # because it carries observed behaviour and the listed one carries none.
    names = {tool.name for tool in tools}
    for tool in listed:
        if tool.name in names:
            continue
        names.add(tool.name)
        tools.append(tool)
    return tools


def scan_tree(root: pathlib.Path) -> list[ToolDef]:
    if root.is_file():
        return scan_file(root)
    tools: list[ToolDef] = []
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__",
            "site-packages", "build", "dist"}
    for path in sorted(root.rglob("*.py")):
        if any(part in skip for part in path.parts):
            continue
        tools.extend(scan_file(path))
    return tools


def find_discrepancies(tools: list[ToolDef]) -> list[Finding]:
    """Contradictions between what a tool declares and what it does.

    These are the only assertions this scanner makes. Each is a statement
    about the server's own manifest being inconsistent with its own code,
    which is true regardless of how the server is deployed.
    """
    findings: list[Finding] = []
    for tool in tools:
        declared, behaviour = tool.declared, tool.behaviour

        near_mutation = behaviour.near_writes + behaviour.near_subprocess
        if declared.get("readOnlyHint") is True and near_mutation:
            evidence = ", ".join(near_mutation)
            findings.append(Finding(
                tool=tool.name, file=tool.file, line=tool.line,
                kind="readonly-violation", severity="HIGH",
                detail=(f"declares readOnlyHint=true but the handler calls {evidence}. "
                        f"Clients use this annotation to skip confirmation prompts."),
            ))

        destroyers = [w for w in behaviour.near_writes
                      if w.split(".")[-1] in DESTRUCTIVE_CALLS]
        if declared.get("destructiveHint") is False and destroyers:
            evidence = ", ".join(destroyers)
            findings.append(Finding(
                tool=tool.name, file=tool.file, line=tool.line,
                kind="destructive-understated", severity="MEDIUM",
                detail=(f"declares destructiveHint=false, meaning additive updates "
                        f"only, but the handler calls {evidence}."),
            ))

        if declared.get("openWorldHint") is False and behaviour.near_network:
            evidence = ", ".join(behaviour.near_network)
            findings.append(Finding(
                tool=tool.name, file=tool.file, line=tool.line,
                kind="closed-world-violation", severity="MEDIUM",
                detail=(f"declares openWorldHint=false but the handler makes network "
                        f"calls ({evidence})."),
            ))

        if not declared and (behaviour.mutates or behaviour.network):
            findings.append(Finding(
                tool=tool.name, file=tool.file, line=tool.line,
                kind="undeclared-risk", severity="LOW",
                detail=("performs writes, subprocess or network calls and declares no "
                        "annotations, so a client has nothing to reason about."),
            ))

    return findings


def policy_scaffold(tools: list[ToolDef], server_name: str) -> str:
    """A deny-by-default policy listing every tool, ready for a human.

    Emitted with no argument constraints on purpose. A scaffold that guessed
    them would be worse than none: it would look reviewed, and the one thing
    nobody can generate from source is which objects a given principal should
    reach.
    """
    lines = [
        f"# Policy scaffold for {server_name}",
        "#",
        "# Generated by detector/mcp_authz_scan.py. NOT ready to deploy.",
        "#",
        "# Every tool the scanner found is listed below, commented out, with the",
        "# parameters that look like resource identifiers called out. Uncomment",
        "# what the agent genuinely needs, add constraints to the identifiers,",
        "# and delete the rest. Anything left commented stays denied.",
        "#",
        "# The constraints are the part a generator cannot write for you: which",
        "# objects a principal may reach is a fact about your tenancy model, not",
        "# about this source code.",
        "",
        "version: 1",
        "default: deny",
        "",
        "rules: []",
        "",
        "# --- tools found, review each -------------------------------------------",
        "",
    ]

    for tool in sorted(tools, key=lambda t: t.name):
        risk = []
        if tool.behaviour.writes:
            risk.append(f"writes({', '.join(tool.behaviour.writes[:3])})")
        if tool.behaviour.subprocess:
            risk.append(f"subprocess({', '.join(tool.behaviour.subprocess[:2])})")
        if tool.behaviour.network:
            risk.append("network")
        if tool.behaviour.validators:
            risk.append(f"validates({', '.join(tool.behaviour.validators[:2])})")

        lines.append(f"#   - id: allow-{tool.name.replace('_', '-')}")
        lines.append(f"#     tools: [{tool.name}]")
        lines.append("#     roles: [REVIEW]")
        if tool.identifier_parameters:
            lines.append("#     arguments:")
            for param in tool.identifier_parameters:
                path_like = any(h in param.lower() for h in ("path", "file", "dir", "folder"))
                hint = "under_path" if path_like else "equals"
                lines.append(f"#       {param}: {{ {hint}: REVIEW }}")
        lines.append(f"#     # {tool.file}:{tool.line}  "
                     f"{' '.join(risk) or 'no risky calls observed'}")
        if tool.declared:
            lines.append(f"#     # declares: {tool.declared}")
        lines.append("#")

    return "\n".join(lines) + "\n"


def report(tools: list[ToolDef], findings: list[Finding]) -> str:
    lines = ["authorization surface", ""]
    if not tools:
        return "no MCP tool definitions found\n"

    width = max(len(t.name) for t in tools)
    lines.append(f"  {'tool'.ljust(width)}  identifiers           behaviour")
    lines.append(f"  {'-' * width}  --------------------  ---------")
    for tool in sorted(tools, key=lambda t: t.name):
        ids = ",".join(tool.identifier_parameters) or "-"
        acts = []
        if tool.behaviour.writes:
            acts.append("write")
        if tool.behaviour.subprocess:
            acts.append("exec")
        if tool.behaviour.network:
            acts.append("net")
        if tool.behaviour.validators:
            acts.append("validated")
        lines.append(f"  {tool.name.ljust(width)}  {ids[:20]:<20}  {','.join(acts) or 'read'}")

    lines.append("")
    lines.append(f"tools:              {len(tools)}")
    lines.append(f"  take an identifier: {sum(1 for t in tools if t.identifier_parameters)}")
    lines.append(f"  mutate state:       {sum(1 for t in tools if t.behaviour.mutates)}")
    lines.append(f"  declare annotations:{sum(1 for t in tools if t.declared)}")
    lines.append(f"  show a validator:   {sum(1 for t in tools if t.behaviour.validators)}")

    if findings:
        lines.append("")
        lines.append("--- declared versus actual ---")
        for f in findings:
            lines.append(f"  {f.severity:<7} {f.kind:<26} {f.tool}")
            lines.append(f"          {f.detail}")
            lines.append(f"          {f.file}:{f.line}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Enumerate an MCP server's authorization surface.")
    ap.add_argument("path", type=pathlib.Path)
    ap.add_argument("--policy-out", type=pathlib.Path, default=None)
    ap.add_argument("--json-out", type=pathlib.Path, default=None)
    ap.add_argument("--fail-on-discrepancy", action="store_true",
                    help="exit 1 if a declared-versus-actual mismatch is found")
    args = ap.parse_args()

    if not args.path.exists():
        print(f"::error::not found: {args.path}", file=sys.stderr)
        return 2

    tools = scan_tree(args.path)
    findings = find_discrepancies(tools)
    print(report(tools, findings))

    if args.policy_out:
        args.policy_out.parent.mkdir(parents=True, exist_ok=True)
        args.policy_out.write_text(policy_scaffold(tools, args.path.name), encoding="utf-8")
        print(f"\npolicy scaffold written to {args.policy_out}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({
            "tools": [t.as_dict() for t in tools],
            "findings": [dataclasses.asdict(f) for f in findings],
        }, indent=2), encoding="utf-8")

    if args.fail_on_discrepancy and findings:
        print(f"\n::error::{len(findings)} declared-versus-actual discrepancy(ies)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
