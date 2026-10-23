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

Read only. Nothing is imported, installed, executed or connected to.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import sys

HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

# Methods that register one tool. `setRequestHandler` is excluded for the same
# reason `call_tool` is excluded on the Python side: it registers the dispatcher
# for every tool a low-level server exposes, and those tools are returned as
# data from a list handler, which a static reader cannot enumerate. A server
# built that way honestly reports zero tools here.
REGISTER_METHODS = frozenset({"registerTool", "tool", "addTool"})

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


def _resolve(node, bindings: dict, depth: int = 0):
    """Follow identifiers to the node they were bound to."""
    if node is None or depth > MAX_RESOLVE_DEPTH:
        return None
    if node.type == "identifier":
        return _resolve(bindings.get(_text(node, b"")), bindings, depth + 1)
    return node


def _resolve_named(node, bindings: dict, src: bytes, depth: int = 0):
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


def _tools_in(root, src: bytes, path: pathlib.Path) -> list[TsTool]:
    bindings = _bindings(root, src)
    tools: list[TsTool] = []

    for node in _walk(root):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        prop = fn.child_by_field_name("property")
        if prop is None or _text(prop, src) not in REGISTER_METHODS:
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
