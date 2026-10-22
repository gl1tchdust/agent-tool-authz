"""Tests for the registry census pipeline.

Two of these are regressions for bugs that cost real time, and both failed
silently rather than loudly, which is the reason they cost real time:

  * `pageinfo.py` read a page with the platform default encoding. On Windows
    that is cp1252, so the first page containing a non-ASCII description threw
    UnicodeDecodeError, the harvest loop read that as "no more data", and the
    sweep stopped at 300 of several thousand records looking like success.

  * `fetch.sh` fed `python print()` output through `mapfile -t`, which strips
    the \\n but leaves the \\r. Every repository name carried a trailing
    carriage return into its URL, so all 20 test repositories reported as
    unreachable and the census would have reported a 100% miss rate.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from census.census import collect, load_shas  # noqa: E402

CENSUS_DIR = pathlib.Path(__file__).resolve().parent.parent / "census"
OFFICIAL = "io.modelcontextprotocol.registry/official"


def _page(servers: list[dict], cursor: str | None = None) -> dict:
    return {"servers": servers, "metadata": {"nextCursor": cursor, "count": len(servers)}}


def _record(name: str, repo_url: str | None, *, latest=True, status="active") -> dict:
    server: dict = {"name": name, "version": "1.0.0", "description": "x"}
    if repo_url is not None:
        server["repository"] = {"url": repo_url, "source": "github"}
    return {"server": server, "_meta": {OFFICIAL: {"isLatest": latest, "status": status}}}


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CENSUS_DIR / script), *args],
        capture_output=True, text=True,
    )


# --------------------------------------------------------------------------
# pageinfo.py
# --------------------------------------------------------------------------

def test_pageinfo_reports_count_and_cursor(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "p0001.json"
    p.write_text(json.dumps(_page([_record("a/b", "https://github.com/a/b")], "a/b:1.0.0")),
                 encoding="utf-8")
    out = _run("pageinfo.py", str(p))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().split("\t") == ["1", "a/b:1.0.0"]


def test_pageinfo_reads_non_ascii_page(tmp_path: pathlib.Path) -> None:
    """Regression: a non-ASCII description used to kill the harvest on Windows.

    The byte that did it was an em dash in a server description. Read as
    cp1252 it raises; the loop treated the failure as end-of-data.
    """
    rec = _record("ai.x/mcp", "https://github.com/x/y")
    rec["server"]["description"] = "Run 150+ AI apps — image, video, audio, 日本語"
    p = tmp_path / "p0001.json"
    p.write_text(json.dumps(_page([rec], "ai.x/mcp:1.0.0"), ensure_ascii=False),
                 encoding="utf-8")

    out = _run("pageinfo.py", str(p))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().split("\t") == ["1", "ai.x/mcp:1.0.0"]


def test_pageinfo_fails_loudly_on_a_truncated_page(tmp_path: pathlib.Path) -> None:
    """A half-written page must be an error, not an empty page.

    An empty page is indistinguishable from the end of the registry, which is
    exactly how the first sweep lost 90% of the data.
    """
    p = tmp_path / "p0001.json"
    p.write_text('{"servers": [{"server"', encoding="utf-8")
    out = _run("pageinfo.py", str(p))
    assert out.returncode != 0
    assert out.stdout.startswith("ERR\t")


# --------------------------------------------------------------------------
# select.py
# --------------------------------------------------------------------------

def _select(tmp_path: pathlib.Path, servers: list[dict]) -> list[dict]:
    pages = tmp_path / "pages"
    pages.mkdir()
    (pages / "p0001.json").write_text(json.dumps(_page(servers)), encoding="utf-8")
    out_file = tmp_path / "candidates.json"
    res = _run("select.py", str(pages), str(out_file))
    assert res.returncode == 0, res.stderr
    return json.loads(out_file.read_text(encoding="utf-8"))


def test_select_keeps_only_current_active_records(tmp_path: pathlib.Path) -> None:
    rows = _select(tmp_path, [
        _record("a/one", "https://github.com/own/live"),
        _record("a/two", "https://github.com/own/old", latest=False),
        _record("a/three", "https://github.com/own/gone", status="deleted"),
    ])
    assert [r["nwo"] for r in rows] == ["own/live"]


def test_select_counts_a_server_not_a_version(tmp_path: pathlib.Path) -> None:
    """The registry stores every published version.

    Counting records rather than current servers would inflate the population:
    in the real data 4700 records reduced to 1398 current servers.
    """
    rows = _select(tmp_path, [
        _record("a/one", "https://github.com/own/repo", latest=False),
        _record("a/one", "https://github.com/own/repo", latest=False),
        _record("a/one", "https://github.com/own/repo", latest=True),
    ])
    assert len(rows) == 1


def test_select_dedupes_a_monorepo(tmp_path: pathlib.Path) -> None:
    rows = _select(tmp_path, [
        _record("a/one", "https://github.com/own/mono"),
        _record("a/two", "https://github.com/own/mono"),
    ])
    assert len(rows) == 1
    assert sorted(rows[0]["servers"]) == ["a/one", "a/two"]


def test_select_ignores_non_github_and_missing_repositories(tmp_path: pathlib.Path) -> None:
    rows = _select(tmp_path, [
        _record("a/gl", "https://gitlab.com/own/repo"),
        _record("a/none", None),
        _record("a/ok", "https://github.com/own/repo"),
    ])
    assert [r["nwo"] for r in rows] == ["own/repo"]


def test_select_normalises_git_suffix_and_trailing_slash(tmp_path: pathlib.Path) -> None:
    """github.com/o/r, .../r.git and .../r/ are one repository, not three."""
    rows = _select(tmp_path, [
        _record("a/1", "https://github.com/own/repo"),
        _record("a/2", "https://github.com/own/repo.git"),
        _record("a/3", "https://github.com/own/repo/"),
    ])
    assert len(rows) == 1
    assert rows[0]["nwo"] == "own/repo"


def test_select_emits_names_without_carriage_returns(tmp_path: pathlib.Path) -> None:
    """Regression for the \\r that made every repository unreachable.

    fetch.sh reads these names into a shell array. A stray \\r rides into the
    URL and the repository 404s, which the script reports as a miss rather
        than as a bug.
    """
    rows = _select(tmp_path, [_record("a/one", "https://github.com/own/repo")])
    for row in rows:
        for key in ("owner", "repo", "nwo"):
            assert "\r" not in row[key] and "\n" not in row[key]


# --------------------------------------------------------------------------
# census.py aggregation
# --------------------------------------------------------------------------

ANNOTATED = textwrap.dedent('''
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations

    mcp = FastMCP("t")

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def read_it(path: str) -> str:
        return open(path).read()
''')

BARE = textwrap.dedent('''
    from mcp.server.fastmcp import FastMCP
    import httpx

    mcp = FastMCP("t")

    @mcp.tool()
    def fetch_it(url: str) -> str:
        return httpx.get(url).text
''')


def _tree(tmp_path: pathlib.Path, repos: dict[str, dict[str, str]]) -> pathlib.Path:
    src = tmp_path / "src"
    for slug, files in repos.items():
        d = src / slug
        d.mkdir(parents=True)
        (d / ".sha").write_text("deadbeef", encoding="utf-8")
        for name, body in files.items():
            (d / name).write_text(body, encoding="utf-8")
    return src


def test_census_counts_the_annotation_rate(tmp_path: pathlib.Path) -> None:
    src = _tree(tmp_path, {
        "own__a": {"server.py": ANNOTATED},
        "own__b": {"server.py": BARE},
    })
    data = collect(src, {})
    assert data["census"]["tools"] == 2
    assert data["census"]["annotated"] == 1
    assert data["census"]["annotation_rate"] == 0.5
    assert data["census"]["by_field"]["readOnlyHint"] == 1


def test_census_separates_examined_from_python_from_tooled(tmp_path: pathlib.Path) -> None:
    """A TypeScript repository is examined and contributes nothing.

    It must still count in the denominator of the population, otherwise the
    census silently describes only the repositories that happened to parse.
    """
    src = _tree(tmp_path, {
        "own__ts": {},                        # no .py at all
        "own__plain": {"util.py": "x = 1\n"},  # python, no MCP tools
        "own__mcp": {"server.py": BARE},
    })
    data = collect(src, {})
    assert data["population"] == {"examined": 3, "with_python": 2, "with_tools": 1}


def test_census_records_the_pinned_sha_per_repo(tmp_path: pathlib.Path) -> None:
    src = _tree(tmp_path, {"own__a": {"server.py": BARE}})
    data = collect(src, {"own/a": "abc1234"})
    row = next(r for r in data["repos"] if r["repo"] == "own/a")
    assert row["sha"] == "abc1234"
    assert data["findings"][0]["sha"] == "abc1234"


def test_census_finding_paths_are_relative_and_posix(tmp_path: pathlib.Path) -> None:
    """Absolute scratch paths in a published result would leak the machine
    they were produced on and break reproducibility checks."""
    src = _tree(tmp_path, {"own__a": {"server.py": BARE}})
    data = collect(src, {})
    assert data["findings"], "expected the undeclared network call to be found"
    for f in data["findings"]:
        assert not pathlib.Path(f["file"]).is_absolute()
        assert "\\" not in f["file"]


def test_census_survives_a_file_that_does_not_parse(tmp_path: pathlib.Path) -> None:
    """Several hundred strangers' repositories will contain Python 2, partial
    files and templated source. One of them must not end the run."""
    src = _tree(tmp_path, {
        "own__broken": {"bad.py": "def (((\n", "server.py": BARE},
    })
    data = collect(src, {})
    assert data["census"]["tools"] == 1


def test_census_handles_an_empty_tree(tmp_path: pathlib.Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    data = collect(src, {})
    assert data["population"]["examined"] == 0
    assert data["census"]["annotation_rate"] == 0.0


# --------------------------------------------------------------------------
# load_shas
# --------------------------------------------------------------------------

def test_load_shas_parses_and_tolerates_a_missing_file(tmp_path: pathlib.Path) -> None:
    assert load_shas(tmp_path / "nope.tsv") == {}
    f = tmp_path / "shas.tsv"
    f.write_text("own/a\tabc\nown/b\tMISS\n", encoding="utf-8")
    assert load_shas(f) == {"own/a": "abc", "own/b": "MISS"}


@pytest.mark.parametrize("line", ["own/a\tabc\r", "  own/a\tabc  "])
def test_load_shas_strips_whitespace_and_carriage_returns(tmp_path: pathlib.Path,
                                                          line: str) -> None:
    f = tmp_path / "shas.tsv"
    f.write_text(line + "\n", encoding="utf-8")
    assert load_shas(f) == {"own/a": "abc"}
