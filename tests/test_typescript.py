"""Tests for reading MCP annotations out of TypeScript servers.

The case that matters is the indirect one. The official servers write

    const config = { annotations: { readOnlyHint: true } };
    server.registerTool(name, config, handler);

so a reader that takes argument two literally finds an identifier and reports
every tool as undeclared. That is the same mistake the Python scanner made
against the official git server before constants were resolved, and here it
would drive the measured annotation rate to zero while looking like a result.

The last test pins the real published corpus and asserts recall against an
independent count, because "49 tools found" means nothing without knowing how
many were there.
"""

from __future__ import annotations

import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from detector import typescript as ts  # noqa: E402

pytestmark = pytest.mark.skipif(
    not ts.available(),
    reason="needs tree-sitter, see requirements-optional.txt",
)

TS_CORPUS = pathlib.Path(".corpus/mcp-servers/src")


def _scan(tmp_path: pathlib.Path, source: str, name: str = "server.ts"):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return ts.scan_file(path)


# ---------------------------------------------------------------------------
# the indirect form, which is what real servers write
# ---------------------------------------------------------------------------

def test_annotations_resolve_through_a_const(tmp_path):
    tools = _scan(tmp_path, """
        const name = "echo";
        const config = {
          title: "Echo Tool",
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
          },
        };
        export const register = (server) => {
          server.registerTool(name, config, async (args) => ({}));
        };
    """)
    assert len(tools) == 1
    assert tools[0].name == "echo"
    assert tools[0].declared == {
        "readOnlyHint": True, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False,
    }


def test_annotations_read_from_an_inline_object(tmp_path):
    tools = _scan(tmp_path, """
        server.registerTool("fetch", {
          annotations: { readOnlyHint: true, openWorldHint: true },
        }, handler);
    """)
    assert tools[0].name == "fetch"
    assert tools[0].declared == {"readOnlyHint": True, "openWorldHint": True}


def test_an_annotations_object_bound_to_its_own_const_resolves(tmp_path):
    """Two hops: the config references a shared annotations constant."""
    tools = _scan(tmp_path, """
        const READ_ONLY = { readOnlyHint: true, openWorldHint: false };
        const config = { title: "t", annotations: READ_ONLY };
        server.registerTool("list", config, handler);
    """)
    assert tools[0].declared == {"readOnlyHint": True, "openWorldHint": False}


def test_a_tool_without_annotations_is_found_and_counted(tmp_path):
    """It must appear in the denominator. Dropping unannotated tools would
    drive the measured rate towards 1.000 by construction."""
    tools = _scan(tmp_path, """
        server.registerTool("bare", { title: "no hints" }, handler);
    """)
    assert len(tools) == 1
    assert tools[0].declared == {}
    assert tools[0].annotated is False


# ---------------------------------------------------------------------------
# what must NOT be read as a tool or a declaration
# ---------------------------------------------------------------------------

def test_set_request_handler_is_not_a_tool(tmp_path):
    """The low-level dispatcher, the same exclusion as Python's call_tool.

    It registers the handler for every tool the server exposes, and those
    tools are returned as data from a list handler. Counting it invents one
    phantom tool per server carrying no annotations, which deflates the rate.
    """
    tools = _scan(tmp_path, """
        server.setRequestHandler(CallToolRequestSchema, async (req) => ({}));
        server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
    """)
    assert tools == []


def test_a_computed_hint_is_not_guessed(tmp_path):
    """A value decided at run time is unknown at rest.

    Recording it as true or false would be inventing data, so the hint is
    simply absent and the tool counts as declaring the hints it does state.
    """
    tools = _scan(tmp_path, """
        server.registerTool("x", {
          annotations: { readOnlyHint: isDryRun(), openWorldHint: true },
        }, handler);
    """)
    assert tools[0].declared == {"openWorldHint": True}


def test_an_unrelated_method_call_is_not_a_tool(tmp_path):
    tools = _scan(tmp_path, """
        server.registerResource("file", config, handler);
        logger.tool("this is not an mcp registration");
    """)
    assert [t.name for t in tools] == ["this is not an mcp registration"]


def test_a_file_that_does_not_parse_returns_nothing(tmp_path):
    """Several hundred strangers' repositories will contain broken source."""
    tools = _scan(tmp_path, "const x = = = ;;; <<<>>>")
    assert isinstance(tools, list)


# ---------------------------------------------------------------------------
# tree walking
# ---------------------------------------------------------------------------

def test_declaration_files_and_vendored_code_are_skipped(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.ts").write_text(
        'server.registerTool("vendored", {}, h);', encoding="utf-8")
    (tmp_path / "types.d.ts").write_text(
        'server.registerTool("declaration", {}, h);', encoding="utf-8")
    (tmp_path / "real.ts").write_text(
        'server.registerTool("real", {}, h);', encoding="utf-8")

    assert [t.name for t in ts.scan_tree(tmp_path)] == ["real"]


def test_tsx_and_js_are_scanned(tmp_path):
    (tmp_path / "a.tsx").write_text('server.registerTool("from_tsx", {}, h);',
                                    encoding="utf-8")
    (tmp_path / "b.js").write_text('server.registerTool("from_js", {}, h);',
                                   encoding="utf-8")
    assert sorted(t.name for t in ts.scan_tree(tmp_path)) == ["from_js", "from_tsx"]


def test_the_line_number_points_at_the_registration(tmp_path):
    tools = _scan(tmp_path, '\n\n\nserver.registerTool("x", {}, h);\n')
    assert tools[0].line == 4


# ---------------------------------------------------------------------------
# against the real published corpus
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not TS_CORPUS.exists(),
                    reason="run ./detector/fetch_corpus.sh first")
def test_official_typescript_servers_are_fully_annotated():
    """Pins the real-world result, measured 2026-10-23.

    Recall is asserted against an independent count rather than taken on
    trust: every `.registerTool(` call site in the corpus is counted by
    regular expression, and the parser must find exactly that many. A parser
    that silently skipped half the registrations would otherwise report a
    confident annotation rate over the half it happened to read.

    The 1.000 is itself evidence for a correction this project published. The
    Python reference corpus annotates 8.7%, and that corpus is SDK and FastMCP
    *examples*, which strip annotations to stay readable. These are working
    servers, and they annotate everything.
    """
    tools = ts.scan_tree(TS_CORPUS)

    call_sites = sum(
        len(re.findall(r"\.registerTool\(", p.read_text(encoding="utf-8", errors="replace")))
        for p in TS_CORPUS.rglob("*.ts")
        if "node_modules" not in p.parts and not p.name.endswith(".d.ts")
    )
    assert call_sites > 0
    assert len(tools) == call_sites, "parser missed registrations the regex can see"

    annotated = [t for t in tools if t.annotated]
    assert len(annotated) == len(tools)
    assert all(t.name != "<unnamed>" for t in tools)


def test_a_binding_inside_a_handler_does_not_shadow_the_module_constant(tmp_path):
    """Regression, found against the official trigger-multi-step-elicitation
    server. An earlier version collected every declarator in the file into one
    flat lookup, so this inner `name` overwrote the module constant and the
    tool came back unnamed, while its annotations still resolved because
    `config` happened not to be shadowed.
    """
    tools = _scan(tmp_path, """
        const name = "the-real-name";
        const config = { annotations: { readOnlyHint: true } };
        export const register = (server) => {
          server.registerTool(name, config, async (_args, ctx) => {
            const name = String(ctx.state.name);
            return { content: [] };
          });
        };
    """)
    assert len(tools) == 1
    assert tools[0].name == "the-real-name"
    assert tools[0].declared == {"readOnlyHint": True}


def test_an_exported_const_is_still_a_module_binding(tmp_path):
    """`export const config = {...}` wraps the declaration one level down."""
    tools = _scan(tmp_path, """
        export const name = "exported";
        export const config = { annotations: { openWorldHint: true } };
        server.registerTool(name, config, handler);
    """)
    assert tools[0].name == "exported"
    assert tools[0].declared == {"openWorldHint": True}
