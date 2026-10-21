"""Detector to gate, end to end.

The two halves of this repository are only worth having together if the output
of one is the input to the other. These tests prove the loop closes:

    scan a server  ->  policy scaffold  ->  a human adds constraints
                                        ->  the gate enforces it
                                        ->  the attack suite scores it

and that the scaffold is useless until a human has touched it, which is the
property that stops it being a false sense of coverage.
"""

from __future__ import annotations

import pathlib
import textwrap

import pytest
import yaml

from detector.mcp_authz_scan import policy_scaffold, scan_file
from src.gate import Gate
from src.mcp_proxy import AUTHORIZATION_DENIED, MCPAuthzProxy
from src.normalize import Principal, ToolCall
from src.policy import Policy

ALICE = Principal(id="alice", roles=frozenset({"user"}))
BOB = Principal(id="bob", roles=frozenset({"user"}))

SERVER = '''
    @server.tool(name="read_file")
    def read_file(path: str) -> str:
        return pathlib.Path(path).read_text()

    @server.tool(name="delete_file")
    def delete_file(path: str) -> str:
        pathlib.Path(path).unlink()
        return "gone"

    @server.tool(name="list_users")
    def list_users() -> list:
        return db.all_users()
'''


@pytest.fixture
def scanned(tmp_path):
    path = tmp_path / "server.py"
    path.write_text(textwrap.dedent(SERVER), encoding="utf-8")
    return scan_file(path)


def test_the_scaffold_denies_everything_until_a_human_edits_it(scanned):
    """The decisive property.

    A generated policy that worked out of the box would be the worst possible
    artefact: it would look like coverage while granting whatever the
    generator guessed. This one grants nothing.
    """
    policy = Policy.from_yaml(policy_scaffold(scanned, "test"))
    gate = Gate(policy, lambda call: "executed")

    for tool in ("read_file", "delete_file", "list_users"):
        decision = gate.check(ToolCall(tool, {"path": "/home/alice/x"}, ALICE))
        assert not decision.allowed, f"{tool} was allowed by an unreviewed scaffold"


def test_the_scaffold_lists_every_tool_the_scanner_found(scanned):
    text = policy_scaffold(scanned, "test")
    for tool in ("read_file", "delete_file", "list_users"):
        assert tool in text, f"{tool} is missing, so a reviewer would never see it"


def test_filling_in_the_scaffold_produces_a_working_policy(scanned):
    """What a human does next: uncomment one rule, add the constraint."""
    reviewed = """
    version: 1
    default: deny
    rules:
      - id: allow-read-file
        tools: [read_file]
        roles: [user]
        arguments:
          path: { under_path: "/home/{principal.id}" }
    """
    policy = Policy.from_yaml(textwrap.dedent(reviewed))
    gate = Gate(policy, lambda call: "contents")

    assert gate.call(ToolCall("read_file", {"path": "/home/alice/notes"}, ALICE)) == "contents"
    assert gate.check(ToolCall("read_file", {"path": "/home/bob/notes"}, ALICE)).allowed is False
    assert gate.check(ToolCall("delete_file", {"path": "/home/alice/x"}, ALICE)).allowed is False


def test_the_reviewed_policy_drives_the_mcp_proxy(scanned):
    """And the same policy object enforces over the wire."""
    reviewed = Policy.from_yaml(textwrap.dedent("""
    version: 1
    default: deny
    rules:
      - id: allow-read-file
        tools: [read_file]
        roles: [user]
        arguments:
          path: { under_path: "/home/{principal.id}" }
    """))

    upstream_calls = []

    def forward(request):
        upstream_calls.append(request)
        return {"jsonrpc": "2.0", "id": request["id"], "result": {"content": []}}

    proxy = MCPAuthzProxy(reviewed, forward)

    def call(path, principal):
        return proxy.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": path}},
        }, principal)

    assert "error" not in call("/home/alice/x", ALICE)
    assert call("/home/bob/x", ALICE)["error"]["code"] == AUTHORIZATION_DENIED
    assert len(upstream_calls) == 1, "only the authorized call reached upstream"


def test_the_scaffold_flags_the_parameters_that_need_constraints(scanned):
    """A reviewer should not have to work out which arguments matter."""
    text = policy_scaffold(scanned, "test")
    assert "path: { under_path: REVIEW }" in text


def test_the_scaffold_records_what_each_tool_does(scanned):
    """So the reviewer can see delete_file is not like read_file."""
    text = policy_scaffold(scanned, "test")
    delete_section = text.split("allow-delete-file")[1].split("#   - id:")[0]
    assert "unlink" in delete_section or "writes" in delete_section


def test_the_real_attack_suite_runs_against_a_policy_from_this_pipeline():
    """The full loop, using the policy that ships with the repository."""
    from benchmark.run import run

    root = pathlib.Path(__file__).resolve().parent.parent
    _, stats = run(root / "attacks" / "cases.yml", root / "attacks" / "policy.yml")

    assert stats["missed"] == 0
    assert stats["broken"] == 0


def test_a_scaffold_for_a_server_with_no_tools_is_still_valid_yaml(tmp_path):
    path = tmp_path / "empty.py"
    path.write_text("x = 1\n", encoding="utf-8")
    doc = yaml.safe_load(policy_scaffold(scan_file(path), "empty"))
    assert doc["default"] == "deny" and doc["rules"] == []
