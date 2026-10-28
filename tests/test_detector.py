"""Tests for the MCP authorization-surface scanner.

Every case here is a pattern that was found in real code and that the scanner
got wrong at some point. They are regression tests in the literal sense: each
one records a specific wrong answer the scanner gave against the official MCP
servers or the SDK examples, so it cannot give it again.
"""

from __future__ import annotations

import pathlib
import textwrap

import pytest
import yaml

from detector.mcp_authz_scan import (
    find_discrepancies,
    policy_scaffold,
    scan_file,
)


def scan(source: str, tmp_path: pathlib.Path):
    path = tmp_path / "server.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return scan_file(path)


# --- finding tools -----------------------------------------------------------


def test_finds_a_decorated_tool(tmp_path):
    tools = scan('''
        @server.tool(name="read_doc")
        def read_doc(doc_id: str) -> str:
            return db.fetch(doc_id)
    ''', tmp_path)
    assert len(tools) == 1
    assert tools[0].name == "read_doc"
    assert tools[0].identifier_parameters == ["doc_id"]


def test_uses_the_declared_name_not_the_function_name(tmp_path):
    tools = scan('''
        @server.tool(name="git_status")
        def status(repo_path: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].name == "git_status"
    assert tools[0].function == "status"


def test_a_non_literal_name_is_preserved_rather_than_guessed(tmp_path):
    """The git server uses name=GitTools.STATUS.value. Silently reporting the
    function name as if it were the advertised tool name would be a lie in the
    inventory."""
    tools = scan('''
        @server.tool(name=GitTools.STATUS.value)
        def status(repo_path: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].name == "<GitTools.STATUS.value>"


def test_ctx_and_self_are_not_treated_as_resource_identifiers(tmp_path):
    tools = scan('''
        @mcp.tool()
        async def search(ctx, query: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].identifier_parameters == ["query"]


# --- annotations: the three real shapes --------------------------------------


def test_inline_tool_annotations(tmp_path):
    tools = scan('''
        @server.tool(
            name="fetch",
            annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
        )
        async def fetch(url: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].declared == {"readOnlyHint": True, "openWorldHint": True}


def test_annotations_via_a_named_constant(tmp_path):
    """The git server assigns annotations once and reuses them across eight
    tools. Reading only inline literals reported all eight as undeclared."""
    tools = scan('''
        READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False)

        @server.tool(name="status", annotations=READ_ONLY)
        def status(repo_path: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].declared == {"readOnlyHint": True, "destructiveHint": False}


def test_annotations_via_a_factory_function(tmp_path):
    """Also from the git server: annotations=writes(destructive=False, ...).

    Values come partly from the factory's literals and partly from the call
    site, so both have to be resolved.
    """
    tools = scan('''
        def writes(*, destructive: bool, idempotent: bool) -> ToolAnnotations:
            return ToolAnnotations(
                read_only_hint=False,
                destructive_hint=destructive,
                idempotent_hint=idempotent,
                open_world_hint=False,
            )

        @server.tool(name="add", annotations=writes(destructive=False, idempotent=True))
        def add(repo_path: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].declared == {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False,
    }


def test_camelcase_dict_annotations(tmp_path):
    tools = scan('''
        @server.tool(name="t", annotations={"readOnlyHint": True})
        def t(path: str) -> str:
            return ""
    ''', tmp_path)
    assert tools[0].declared == {"readOnlyHint": True}


# --- behaviour: the over-matching that made it useless -----------------------


def test_dict_get_is_not_a_network_call(tmp_path):
    """`.get()` is the most common method name in Python. Matching the bare
    verb reported token.claims.get("sub") as a network call and produced
    twenty false positives across the SDK examples."""
    tools = scan('''
        @server.tool(name="claims")
        def claims() -> dict:
            token = get_access_token()
            return {"sub": token.claims.get("sub")}
    ''', tmp_path)
    assert tools[0].behaviour.network == []


def test_an_imported_module_verb_is_a_network_call(tmp_path):
    """And the fix must still catch the real thing, under any library name."""
    tools = scan('''
        import httpx2

        @server.tool(name="show_map")
        def show_map(query: str) -> str:
            return httpx2.get("https://geocode.example/q").text
    ''', tmp_path)
    assert tools[0].behaviour.network == ["httpx2.get"]


def test_an_aliased_import_is_still_caught(tmp_path):
    tools = scan('''
        import requests as rq

        @server.tool(name="f")
        def f(url: str) -> str:
            return rq.post(url).text
    ''', tmp_path)
    assert tools[0].behaviour.network == ["rq.post"]


def test_asyncio_run_is_not_subprocess_execution(tmp_path):
    tools = scan('''
        import asyncio

        @server.tool(name="t")
        def t(x: str) -> str:
            return asyncio.run(work(x))
    ''', tmp_path)
    assert tools[0].behaviour.subprocess == []


def test_real_subprocess_is_caught(tmp_path):
    tools = scan('''
        import subprocess

        @server.tool(name="t")
        def t(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout
    ''', tmp_path)
    assert tools[0].behaviour.subprocess == ["subprocess.run"]


def test_repo_commit_reads_but_index_commit_writes(tmp_path):
    """GitPython's repo.commit(rev) resolves a commit; index.commit() creates
    one. Matching the bare verb reported the read-only `show` tool as a
    readOnlyHint violation."""
    reads = scan('''
        @server.tool(name="show")
        def show(repo_path: str, revision: str) -> str:
            return repo.commit(revision).message
    ''', tmp_path)
    assert reads[0].behaviour.writes == []

    writes = scan('''
        @server.tool(name="commit")
        def commit(repo_path: str, message: str) -> str:
            return index.commit(message).hexsha
    ''', tmp_path)
    assert writes[0].behaviour.writes == ["index.commit"]


# --- following calls ---------------------------------------------------------


def test_a_one_line_delegate_is_followed_into_its_helper(tmp_path):
    """Real handlers delegate. Looking only at the handler body reported a git
    server with add, commit and reset as `mutate state: 0`."""
    tools = scan('''
        def do_write(p):
            pathlib.Path(p).write_text("x")

        @server.tool(name="save")
        def save(path: str) -> str:
            return do_write(path)
    ''', tmp_path)
    assert "write_text" in tools[0].behaviour.writes


def test_an_attribute_call_is_not_resolved_to_a_module_function(tmp_path):
    """The bug that followed a read-only git tool into the commit handler:
    repo.commit(...) matched a module-level function named commit."""
    tools = scan('''
        def commit(path: str) -> str:
            pathlib.Path(path).unlink()
            return "deleted"

        @server.tool(name="show")
        def show(revision: str) -> str:
            return repo.commit(revision).message
    ''', tmp_path)
    assert tools[0].behaviour.writes == [], "obj.commit() is not the module's commit()"


def test_recursion_does_not_hang_the_scanner(tmp_path):
    tools = scan('''
        def a(x):
            return b(x)

        def b(x):
            return a(x)

        @server.tool(name="t")
        def t(path: str) -> str:
            return a(path)
    ''', tmp_path)
    assert tools[0].name == "t"


# --- discrepancies -----------------------------------------------------------


def test_readonly_true_with_a_write_is_a_finding(tmp_path):
    tools = scan('''
        @server.tool(name="t", annotations=ToolAnnotations(read_only_hint=True))
        def t(path: str) -> str:
            pathlib.Path(path).write_text("x")
            return ""
    ''', tmp_path)
    kinds = [f.kind for f in find_discrepancies(tools)]
    assert "readonly-violation" in kinds


def test_an_additive_write_is_not_destructive(tmp_path):
    """MCP defines destructiveHint as 'may perform destructive updates' versus
    'only additive updates', so creating is not destroying."""
    tools = scan('''
        @server.tool(name="t", annotations=ToolAnnotations(destructive_hint=False))
        def t(path: str) -> str:
            pathlib.Path(path).write_text("new content")
            return ""
    ''', tmp_path)
    kinds = [f.kind for f in find_discrepancies(tools)]
    assert "destructive-understated" not in kinds


def test_an_actual_delete_is_destructive(tmp_path):
    tools = scan('''
        @server.tool(name="t", annotations=ToolAnnotations(destructive_hint=False))
        def t(path: str) -> str:
            pathlib.Path(path).unlink()
            return ""
    ''', tmp_path)
    kinds = [f.kind for f in find_discrepancies(tools)]
    assert "destructive-understated" in kinds


def test_a_correctly_annotated_tool_produces_nothing(tmp_path):
    """The quietest and most important test: no finding on correct code."""
    tools = scan('''
        @server.tool(name="t", annotations=ToolAnnotations(read_only_hint=True))
        def t(path: str) -> str:
            return pathlib.Path(path).read_text()
    ''', tmp_path)
    assert find_discrepancies(tools) == []


def test_a_read_only_tool_with_no_annotations_is_not_flagged(tmp_path):
    """undeclared-risk fires on risk, not on the absence of annotations.
    Otherwise every tool in a corpus where 264 of 289 declare nothing becomes
    a finding, which is noise, not a result."""
    tools = scan('''
        @server.tool(name="t")
        def t(x: str) -> str:
            return x.upper()
    ''', tmp_path)
    assert find_discrepancies(tools) == []


# --- policy scaffold ---------------------------------------------------------


def test_the_scaffold_is_deny_by_default_and_fully_commented(tmp_path):
    """A scaffold that was accidentally deployable would be worse than none."""
    tools = scan('''
        @server.tool(name="read_doc")
        def read_doc(doc_id: str) -> str:
            return ""
    ''', tmp_path)
    text = policy_scaffold(tools, "test")
    doc = yaml.safe_load(text)

    assert doc["default"] == "deny"
    assert doc["rules"] == [], "every generated rule must be commented out"
    assert "read_doc" in text, "but the tool is still listed for review"
    assert "REVIEW" in text, "and the constraints are marked for a human"


def test_the_scaffold_marks_path_parameters_for_path_constraints(tmp_path):
    tools = scan('''
        @server.tool(name="read_file")
        def read_file(path: str) -> str:
            return ""
    ''', tmp_path)
    assert "under_path" in policy_scaffold(tools, "t")


def test_the_scaffold_parses_as_yaml_even_with_no_tools():
    doc = yaml.safe_load(policy_scaffold([], "empty"))
    assert doc["default"] == "deny"


# --- the committed ground truth ----------------------------------------------


def test_the_labels_file_is_internally_consistent():
    """The README quotes precision and recall from this file."""
    path = pathlib.Path(__file__).resolve().parent.parent / "detector" / "labels" / "mcp-corpus.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))

    findings = doc["findings"]
    tp = sum(1 for f in findings if f["verdict"] == "true_positive")
    fp = sum(1 for f in findings if f["verdict"] == "false_positive")
    misses = len(doc["known_misses"])
    stated = doc["accuracy"]

    assert stated["findings"] == len(findings)
    assert stated["true_positives"] == tp
    assert stated["false_positives"] == fp
    assert stated["known_misses"] == misses
    assert round(tp / (tp + fp), 3) == stated["precision"]
    assert round(tp / (tp + misses), 3) == stated["recall"]
    assert doc["total_tools"] == sum(c["tools"] for c in doc["corpus"])


def test_every_finding_carries_a_verdict_and_a_reason():
    path = pathlib.Path(__file__).resolve().parent.parent / "detector" / "labels" / "mcp-corpus.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    for f in doc["findings"]:
        assert f["verdict"] in ("true_positive", "false_positive")
        assert f.get("note"), f"{f['tool']} has no justification"


def test_low_level_call_tool_dispatcher_is_not_a_tool(tmp_path):
    """Regression: @server.call_tool() registers the dispatcher, not a tool.

    On a low-level Server this one function handles every tool the server
    exposes. Treating it as a tool definition invented a phantom tool per
    server, named after the dispatcher, taking (name, arguments), carrying the
    aggregated behaviour of everything it could reach.

    In the registry census that was 65 of 285 tools in the largest repository
    and 92 files overall. Nobody annotates a dispatcher, so every phantom
    counted as unannotated and pushed the measured annotation rate down.
    """
    src = tmp_path / "lowlevel.py"
    src.write_text(
        "from mcp.server import Server\n"
        "import httpx\n"
        "\n"
        "server = Server('x')\n"
        "\n"
        "@server.call_tool()\n"
        "async def handle_call_tool(name: str, arguments: dict):\n"
        "    return httpx.post('https://example.com/' + name, json=arguments).text\n",
        encoding="utf-8",
    )
    assert scan_file(src) == []


def test_a_real_tool_decorator_is_still_matched(tmp_path):
    """Control for the test above: excluding call_tool must not exclude tool."""
    src = tmp_path / "fastmcp_server.py"
    src.write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "import httpx\n"
        "\n"
        "mcp = FastMCP('x')\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch(url: str) -> str:\n"
        "    return httpx.get(url).text\n",
        encoding="utf-8",
    )
    tools = scan_file(src)
    assert [t.name for t in tools] == ["fetch"]


# --- the low-level manifest, where tools are data ----------------------------


def test_tools_declared_in_a_list_tools_handler_are_counted(tmp_path):
    """The other half of the call_tool exclusion.

    Skipping the dispatcher was right, but it left low-level servers
    reporting zero tools. The manifest is where they are declared, and it is
    as static as any decorator.
    """
    tools = scan('''
        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return [
                types.Tool(
                    name="read_file",
                    inputSchema={},
                    annotations=types.ToolAnnotations(readOnlyHint=True),
                ),
                types.Tool(name="write_file", inputSchema={}),
            ]
    ''', tmp_path)
    assert [t.name for t in tools] == ["read_file", "write_file"]
    assert tools[0].declared == {"readOnlyHint": True}
    assert tools[1].declared == {}


def test_a_listed_tool_has_no_behaviour_and_so_no_findings(tmp_path):
    """The implementation is in the dispatcher, and is not attributed.

    Guessing which branch of `call_tool` belongs to which name is exactly the
    semantic inference that scored 0 of 4 on the labelled sample. Reading the
    declaration without the code means the tool counts toward the annotation
    rate and toward nothing else.
    """
    tools = scan('''
        @server.list_tools()
        async def list_tools():
            return [Tool(name="wipe", inputSchema={})]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            os.unlink(arguments["path"])
    ''', tmp_path)
    assert len(tools) == 1
    assert tools[0].behaviour.writes == []
    assert find_discrepancies(tools) == []


def test_a_listed_tool_list_resolves_through_a_constant(tmp_path):
    tools = scan('''
        TOOLS = [Tool(name="ping", annotations={"readOnlyHint": True})]

        @server.list_tools()
        async def list_tools():
            return TOOLS
    ''', tmp_path)
    assert len(tools) == 1
    assert tools[0].name == "ping"
    assert tools[0].declared == {"readOnlyHint": True}


def test_starred_and_concatenated_tool_lists_are_flattened(tmp_path):
    """Grouping the manifest by permission is the case worth counting."""
    tools = scan('''
        READ = [Tool(name="get", annotations={"readOnlyHint": True})]
        WRITE = [Tool(name="put", annotations={"readOnlyHint": False})]

        @server.list_tools()
        async def list_tools():
            return [*READ, *WRITE]
    ''', tmp_path)
    assert [t.name for t in tools] == ["get", "put"]

    concatenated = scan('''
        READ = [Tool(name="get")]
        WRITE = [Tool(name="put")]

        @server.list_tools()
        async def list_tools():
            return READ + WRITE
    ''', tmp_path)
    assert [t.name for t in concatenated] == ["get", "put"]


def test_a_computed_manifest_is_not_invented(tmp_path):
    """Built at run time, so unknown at rest. Undercount, never guess."""
    tools = scan('''
        @server.list_tools()
        async def list_tools():
            return [Tool(**spec) for spec in registry.values()]
    ''', tmp_path)
    assert tools == []


def test_tool_annotations_is_not_mistaken_for_a_tool(tmp_path):
    """Only a construction whose last name is exactly `Tool` counts."""
    tools = scan('''
        @server.list_tools()
        async def list_tools():
            return [ToolAnnotations(readOnlyHint=True), ToolResult(ok=True)]
    ''', tmp_path)
    assert tools == []


def test_a_branching_manifest_counts_each_tool_once(tmp_path):
    """Two returns sharing a tool would otherwise count it twice."""
    tools = scan('''
        @server.list_tools()
        async def list_tools():
            if admin:
                return [Tool(name="read"), Tool(name="write")]
            return [Tool(name="read")]
    ''', tmp_path)
    assert [t.name for t in tools] == ["read", "write"]


def test_a_manifest_delegated_to_a_helper_is_followed(tmp_path):
    """`return get_all_tools()`, six occurrences in the largest repo.

    Those six are annotated, so skipping the hop would have biased the rate
    upward here, the opposite direction from the TypeScript gap. The
    direction of a miss is not something to assume.
    """
    tools = scan('''
        def get_all_tools():
            return [
                Tool(name="list_teams", annotations={"readOnlyHint": True}),
                Tool(name="send_message"),
            ]

        @server.list_tools()
        async def list_tools():
            return get_all_tools()
    ''', tmp_path)
    assert [t.name for t in tools] == ["list_teams", "send_message"]
    assert tools[0].declared == {"readOnlyHint": True}


def test_a_cyclic_helper_does_not_hang_the_scanner(tmp_path):
    """The depth bound has to stop mutual recursion, not just deep nesting."""
    tools = scan('''
        def a():
            return b()

        def b():
            return a()

        @server.list_tools()
        async def list_tools():
            return a()
    ''', tmp_path)
    assert tools == []


def test_two_transports_sharing_one_manifest_count_it_once(tmp_path):
    """Regression: 22 tools reported for 11 real ones.

    The msteams server in the registry corpus registers a list_tools handler
    per transport, stdio and HTTP, each returning the same manifest. Dedup
    has to be per file, not per handler.
    """
    tools = scan('''
        def get_all_tools():
            return [Tool(name="a"), Tool(name="b")]

        def run_stdio():
            @app.list_tools()
            async def list_tools():
                return get_all_tools()

        def run_http():
            @app.list_tools()
            async def list_tools_http():
                return get_all_tools()
    ''', tmp_path)
    assert [t.name for t in tools] == ["a", "b"]


def test_a_decorated_tool_wins_over_the_same_name_in_a_manifest(tmp_path):
    """The decorator carries observed behaviour; the manifest entry does not."""
    tools = scan('''
        import os

        @mcp.tool()
        def wipe(path: str):
            os.unlink(path)

        @server.list_tools()
        async def list_tools():
            return [Tool(name="wipe", annotations={"readOnlyHint": True})]
    ''', tmp_path)
    assert len(tools) == 1
    # the decorator's observed behaviour survived, so the listed entry lost
    assert tools[0].behaviour.writes == ["unlink"]
    assert tools[0].declared == {}
