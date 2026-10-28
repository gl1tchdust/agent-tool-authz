#!/usr/bin/env python3
"""Read MCP tool annotations out of TypeScript and JavaScript servers.

    python -m detector.typescript path/to/server/src

Python's `ast` covers one language, and the registry is mostly not that
language: a GitHub search for `mcp-server language:typescript` returned 48,619
repositories on 2026-10-22. This module closes the annotation half of that gap
using tree-sitter, so the census rate describes the registry rather than the
Python part of it.

Deliberately NOT a port of the whole detector. `mcp_authz_scan.py` also decides
whether a handler writes, executes or reaches the network, and compares that to
what the tool declares. Measured against a random sample of the Python census,
that comparison scored 10 of 10 on the structural `undeclared-risk` check and 0
of 4 on the two semantic ones, because deciding whether an operation "modifies
the environment" misreads telemetry logging and subprocess isolation.

Porting the half that does not work would double the surface and the wrong
answers with it. So this reads declarations only, which is a parse with no
judgement in it, and is the input the census actually needs.

The shape it has to handle is not the inline literal:

    const config = { annotations: { readOnlyHint: true } };
    server.registerTool(name, config, handler);

`registerTool` is passed identifiers. Reading argument two literally finds a
variable and reports the tool as undeclared, which is the same mistake the
Python scanner made against the official git server before `ConstantResolver`
existed. Module-level `const` bindings are resolved here for the same reason.

The other shape is the low-level one, where tools are data rather than calls:

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [{ name: "read_file", annotations: { readOnlyHint: true } }],
    }));

`_listed_tools` reads those. They are 248 call sites in the registry census,
and because a hand-written array is the code least likely to annotate
anything, omitting them pushed the measured rate up rather than down.

Read only. Nothing is imported, installed, executed or connected to.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import sys

HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

# Methods that register one tool each.
#
# `setRequestHandler` is not one of them, and never counts as a tool itself:
# it installs a handler, the same way Python's `call_tool` installs the
# dispatcher for every tool at once. But a `ListToolsRequestSchema` handler
# *returns* the tool definitions, annotations included, and when that return
# value is an array literal it is as readable at rest as any `registerTool`
# call. `_listed_tools` reads those. See its docstring for what stays
# unreadable and why that direction of error is the safe one.
REGISTER_METHODS = frozenset({"registerTool", "tool", "addTool"})

# The request schema whose handler returns the tool list. Matched by the
# identifier as written, which is how every server in the corpus spells it.
LIST_TOOLS_SCHEMA = "ListToolsRequestSchema"

SKIP_DIRS = {".git", "node_modules", "dist", "build", "out", ".next", "coverage"}

# One identifier hop is enough for `const config = {...}` followed by
# `registerTool(name, config, h)`. Chains longer than this are rare and a miss
# costs a tool counted as undeclared, which understates the rate rather than
# inventing one.
MAX_RESOLVE_DEPTH = 3


@dataclasses.dataclass
class TsTool:
    name: str
    file: str
    line: int
    declared: dict[str, bool]

    @property
    def annotated(self) -> bool:
        return bool(self.declared)


class _Unavailable(RuntimeError):
    """tree-sitter is not installed."""


def _parser():
    try:
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
    except ImportError as exc:  # pragma: no cover - exercised by the skip
        raise _Unavailable(
            "TypeScript support needs tree-sitter. "
            "pip install 'tree-sitter>=0.23,<0.25' tree-sitter-typescript==0.23.2"
        ) from exc
    return Parser(Language(tsts.language_typescript())), Parser(Language(tsts.language_tsx()))


def available() -> bool:
    try:
        _parser()
    except _Unavailable:
        return False
    return True


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _bindings(root, src: bytes) -> dict:
    """Module-level `const X = <value>` only, by name.

    Top level specifically, not every declarator in the file. An earlier
    version walked the whole tree, so a binding nested inside a handler
    overwrote the module constant of the same name. In the official
    `trigger-multi-step-elicitation` server that is literally

        const name = "trigger-multi-step-elicitation";   // line 31
        ...
        const name = String(state.name);                 // line 130, in the handler

    and the tool came back unnamed while its annotations still resolved
    correctly, because `config` happened not to be shadowed. A scanner that
    reads the right declaration for one field and the wrong one for another,
    from the same lookup, is the kind of thing that only shows up against real
    code.

    Restricting to the top level is the whole fix. A tool registered inside a
    factory that closes over a local constant resolves to nothing rather than
    to the wrong thing, which costs a declaration read as absent and
    understates the rate instead of inventing one.
    """
    out = {}
    for statement in root.named_children:
        # `export const config = {...}` wraps the declaration one level down.
        node = statement
        if node.type == "export_statement":
            inner = node.child_by_field_name("declaration")
            if inner is None:
                continue
            node = inner
        if node.type not in ("lexical_declaration", "variable_declaration"):
            continue
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                out.setdefault(_text(name, src), value)
    return out


def _resolve_named(node, bindings: dict, src: bytes, depth: int = 0):
    """Follow identifiers to the node they were bound to."""
    if node is None or depth > MAX_RESOLVE_DEPTH:
        return None
    if node.type == "identifier":
        return _resolve_named(bindings.get(_text(node, src)), bindings, src, depth + 1)
    return node


def _property(obj, key: str, src: bytes):
    """The value of `key` in an object literal, or None."""
    if obj is None or obj.type != "object":
        return None
    for child in obj.named_children:
        if child.type != "pair":
            continue
        k = child.child_by_field_name("key")
        if k is None:
            continue
        if _text(k, src).strip("\"'`") == key:
            return child.child_by_field_name("value")
    return None


def _annotations(obj, bindings: dict, src: bytes) -> dict[str, bool]:
    ann = _resolve_named(_property(obj, "annotations", src), bindings, src)
    if ann is None or ann.type != "object":
        return {}
    out: dict[str, bool] = {}
    for hint in HINTS:
        value = _resolve_named(_property(ann, hint, src), bindings, src)
        if value is None:
            continue
        # Only a literal counts. A computed value is a declaration whose
        # content is unknown at rest, and guessing it would be inventing data.
        if value.type == "true":
            out[hint] = True
        elif value.type == "false":
            out[hint] = False
    return out


def _array_elements(node, bindings: dict, src: bytes, depth: int = 0) -> list:
    """Elements of an array literal, flattening `...spread` of other arrays.

    `tools: [...readTools, ...writeTools]` is how a server that groups its
    tools by permission assembles the list, and those are exactly the servers
    whose annotations are worth counting. Following the spread costs four
    lines. Not following it would read the whole list as zero tools.
    """
    if node is None or node.type != "array" or depth > MAX_RESOLVE_DEPTH:
        return []
    out = []
    for child in node.named_children:
        if child.type == "spread_element":
            inner = child.named_children[0] if child.named_children else None
            out.extend(_array_elements(_resolve_named(inner, bindings, src),
                                       bindings, src, depth + 1))
        else:
            out.append(child)
    return out


def _listed_tools(call, bindings: dict, src: bytes, path: pathlib.Path) -> list[TsTool]:
    """Tool definitions returned by a ListTools handler, where enumerable.

    A low-level server declares its tools as data rather than through calls:

        server.setRequestHandler(ListToolsRequestSchema, async () => ({
          tools: [{ name: "read_file", annotations: { readOnlyHint: true } }],
        }));

    Those declarations are as static as any `registerTool` argument, so
    leaving them out was a measurement gap rather than a principled
    exclusion. It mattered: 248 call sites in the registry census register
    tools this way, and hand-written low-level arrays are the code *least*
    likely to carry annotations, so omitting them biased the rate upward.

    What stays unreadable is anything computed:

        return { tools: Object.values(tools).map((t) => t.definition) };
        const sanitized = availableTools.map(({ _meta, ...rest }) => rest);

    The array is produced at run time and a static reader that guessed at its
    length would be inventing data. Those resolve to nothing and the server
    reports the tools it states literally, which undercounts rather than
    overcounts. Same direction of error as every other miss in this module.

    Only the first `tools:` pair inside the handler is read, because that is
    the response field; a second one deeper in would be some other object's.
    """
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    named = args.named_children
    if not named or _text(named[0], src).strip() != LIST_TOOLS_SCHEMA:
        return []

    for node in _walk(call):
        if node.type != "pair":
            continue
        key = node.child_by_field_name("key")
        if key is None or _text(key, src).strip("\"'`") != "tools":
            continue
        array = _resolve_named(node.child_by_field_name("value"), bindings, src)
        tools = []
        for element in _array_elements(array, bindings, src):
            obj = _resolve_named(element, bindings, src)
            if obj is None or obj.type != "object":
                continue
            name = _resolve_named(_property(obj, "name", src), bindings, src)
            tools.append(TsTool(
                name=(_text(name, src).strip("\"'`")
                      if name is not None and name.type == "string" else "<unnamed>"),
                file=str(path),
                line=obj.start_point[0] + 1,
                declared=_annotations(obj, bindings, src),
            ))
        return tools
    return []


def _tools_in(root, src: bytes, path: pathlib.Path) -> list[TsTool]:
    bindings = _bindings(root, src)
    tools: list[TsTool] = []
    listed: list[TsTool] = []

    for node in _walk(root):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        prop = fn.child_by_field_name("property")
        if prop is None:
            continue
        method = _text(prop, src)
        if method == "setRequestHandler":
            listed.extend(_listed_tools(node, bindings, src, path))
            continue
        if method not in REGISTER_METHODS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        name = ""
        declared: dict[str, bool] = {}
        for arg in args.named_children:
            resolved = _resolve_named(arg, bindings, src)
            if resolved is None:
                continue
            if resolved.type == "string" and not name:
                name = _text(resolved, src).strip("\"'`")
            elif resolved.type == "object" and not declared:
                declared = _annotations(resolved, bindings, src)

        tools.append(TsTool(
            name=name or "<unnamed>",
            file=str(path),
            line=node.start_point[0] + 1,
            declared=declared,
        ))

    # One manifest per name, for the reason the Python side carries the same
    # rule: a file that sets up both a stdio and an HTTP transport installs a
    # ListTools handler for each, both returning the same array, and counting
    # the manifest twice would inflate the population. A registered tool wins
    # over a listed one of the same name, being the more specific statement.
    names = {tool.name for tool in tools}
    for tool in listed:
        if tool.name in names:
            continue
        names.add(tool.name)
        tools.append(tool)
    return tools


def scan_file(path: pathlib.Path) -> list[TsTool]:
    ts, tsx = _parser()
    try:
        src = path.read_bytes()
    except OSError:
        return []
    parser = tsx if path.suffix == ".tsx" else ts
    try:
        tree = parser.parse(src)
    except (ValueError, RecursionError):
        return []
    return _tools_in(tree.root_node, src, path)


def scan_tree(root: pathlib.Path) -> list[TsTool]:
    if root.is_file():
        return scan_file(root)
    tools: list[TsTool] = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".ts", ".tsx", ".js", ".mjs"):
            continue
        if path.name.endswith(".d.ts"):
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        tools.extend(scan_file(path))
    return tools


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=pathlib.Path)
    args = ap.parse_args()

    try:
        tools = scan_tree(args.root)
    except _Unavailable as exc:
        print(exc, file=sys.stderr)
        return 2

    annotated = [t for t in tools if t.annotated]
    for tool in tools:
        flags = ",".join(f"{k}={str(v).lower()}" for k, v in sorted(tool.declared.items()))
        print(f"  {tool.name:<34} {flags or '(no annotations)'}")
    print()
    print(f"tools                    {len(tools)}")
    print(f"declaring any annotation {len(annotated)}")
    if tools:
        print(f"annotation rate          {len(annotated) / len(tools):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
