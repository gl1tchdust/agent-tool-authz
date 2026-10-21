# Nobody is checking whether MCP tools do what they say

**Shivam Mahajan** · October 2026 · [gl1tchdust/agent-tool-authz](https://github.com/gl1tchdust/agent-tool-authz)

MCP tools declare their own risk profile. Agents read those declarations to
decide what to run without asking a human. The specification says the
declarations are untrusted and offers no way to check them, and the scanners
built for MCP do not check them either.

I built something that does, measured it against 289 tools in four real
codebases, and got **precision 0.800, recall 0.667**. Every label is checked
in. So are the four bugs the real corpus found in my own detector, one of
which produced a HIGH-severity finding against a read-only tool.

---

## 1. The gap

An MCP tool can carry annotations describing what it does:

```python
@server.tool(
    name="fetch",
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        open_world_hint=True,
    ),
)
```

Clients use these to decide what to auto-approve. A tool marked
`readOnlyHint: true` is the kind of thing an agent runs without stopping to
ask, because by its own account it cannot break anything.

The specification is clear-eyed about the risk. From MCP 2026-07-28, Server
Tools:

> clients **MUST** consider tool annotations to be untrusted unless they come
> from trusted servers.

That is correct, and it is advice with nothing behind it. "Trust annotations
only from servers you trust" hands the decision to an operator who has no
mechanism to establish the trust. Meanwhile the annotation is a claim *about
code that is sitting right there*, and the claim is checkable.

### What existing scanners check

The MCP scanner space is not empty. Snyk ships `agent-scan`, NVIDIA ships
SkillSpector, Tencent ships AI-Infra-Guard, plus dedicated tools like
`mcp-watch` and `ramparts`. Before building anything I checked what they
actually do, because duplicating them would be worthless.

They answer a different question: **is this server malicious?** Tool
poisoning, prompt injection hidden in descriptions, credential leakage,
server spoofing, supply chain.

None of them checks whether a handler's behaviour matches its declaration:

- **ramparts** says so in its own README: it analyses "static metadata,
  configurations, and skill files" rather than server code.
- **mcp-watch** has an `access-control` category. I read
  `src/scanner/scanners/PermissionScanner.ts`: it is a regex for
  consent-fatigue wording, matching patterns like `approve.*loop` and
  `confirm.*many`.

That is the gap. It exists for the same reason authorization bugs dominate API
security: the question is application-specific, so no vendor ships a rule for
it.

---

## 2. Method

`mcp_authz_scan.py` parses Python MCP servers with `ast` and asks three
questions per tool:

1. **What does it accept?** Parameters, and which of them name a resource
   rather than configure an action.
2. **What does it do?** Writes, subprocess execution, network calls, and
   whether a caller-supplied value passes through anything validator-shaped.
3. **What does it claim?** The MCP annotations it declares.

Then: do 2 and 3 agree? Four contradictions are reported.

| Kind | Condition |
|---|---|
| `readonly-violation` | declares `readOnlyHint: true`, handler mutates |
| `destructive-understated` | declares `destructiveHint: false`, handler destroys rather than adds |
| `closed-world-violation` | declares `openWorldHint: false`, handler reaches the network |
| `undeclared-risk` | writes, executes or reaches the network, declares nothing |

### What it refuses to claim

Not that a server is vulnerable. Most MCP servers are single-user local tools
where a caller-supplied path is the entire product; scoping it would break
them. The official reference servers are in the corpus and **none is reported
as insecure, because none is**.

So the output is an inventory with evidence. The only assertion is the
declared-versus-actual mismatch, because that is a contradiction *inside the
server's own manifest* and holds however it is deployed.

---

## 3. Results

Four codebases, pinned to commits, all permissively licensed. Read only:
nothing was imported, executed or connected to.

| Corpus | Tools |
|---|---|
| `modelcontextprotocol/servers` (git) | 12 |
| `modelcontextprotocol/servers` (fetch) | 1 |
| `modelcontextprotocol/python-sdk` examples | 119 |
| `PrefectHQ/fastmcp` examples | 157 |
| **Total** | **289** |

**5 findings. 4 true positives, 1 false positive, 2 known misses.**

**Precision 0.800 · Recall 0.667**

### The true positives

**`textme`** (appears in both the Python SDK and FastMCP examples). Calls
`client.post` against `api.surgemsg.com` and **sends an actual SMS** to a
configured phone number. No annotations at all. A client approving this has no
way to know it has an effect in the physical world.

**`get_test_pdf_from_url`** (FastMCP). `session.get(url)` where `url` is a
caller-supplied parameter. Fetches an arbitrary URL on the caller's say-so and
declares nothing — an SSRF-shaped surface in an example file, which is to say
in code that will be copied.

**`show_map`** (FastMCP). `httpx2.get()` against a geocoding API, undeclared.
This one was *initially missed*; see §4.

### The false positive

The official git server's `commit` tool, flagged `destructive-understated`
because `git_commit()` calls `unlink()` on `.git/MERGE_HEAD` after a merge.
That is internal plumbing. A commit is additive, `destructive_hint=False` is
correct, and the scanner is wrong.

**It is left unfixed.** Narrowing the rule until this one case disappeared
would be fitting to a single example. A published 0.800 that anyone can
re-derive is worth more than a 1.000 that was tuned into existence.

### A result that is not a finding

Of 289 tools, **25 declare any annotations at all.** The mismatch problem is
real but small today, because the thing being mismatched is mostly absent. If
clients increasingly gate auto-approval on annotations, that ratio is the
number to watch.

---

## 4. Four bugs the corpus found in the detector

Everything below is a wrong answer my scanner gave against real code. Each is
now a regression test. They are worth reading because they are the ways this
class of tool fails quietly.

### Bare `.get()` is not a network call

`get` was in my network-call set. It matched `token.claims.get("sub")` in the
FastMCP auth example, producing **20 false positives** across the SDK examples
before I looked at one closely.

`.get()` is the most common method name in Python. The fix was to match HTTP
verbs only when the receiver is a module that was imported — which also fixed
`show_map`, where the receiver is `httpx2`, a package name no hardcoded list
would have contained.

### `repo.commit()` is a read

GitPython's `repo.commit(rev)` resolves a revision. `repo.index.commit()`
creates one. Matching the bare verb reported the read-only `show` tool as a
`readOnlyHint` violation.

### Attribute calls are not module functions

The worst one. Having matched `repo.commit(...)`, my interprocedural analysis
resolved the name `commit` against module-level functions — and found the
`commit` **tool handler**, followed into it, and inherited its file deletions.

`git show` was reported as HIGH severity with a plausible explanation
attached. It was caught only because "git show is destructive" is obviously
absurd to someone who knows git. **A scanner that is confidently wrong is
worse than one that is quiet**, and nothing in the output distinguished this
finding from the true ones.

### Handlers are one-line delegates

```python
def commit(repo_path: str, message: str) -> str:
    return git_commit(open_repo(repo_path), message)
```

Analysing only the handler body reported a git server with add, commit and
reset as `mutate state: 0`. Not a near-miss — the opposite of the truth.
Following module-local helpers, bounded at three levels, fixed it.

---

## 5. Limits

- **Python only.** 48,435 TypeScript MCP server repositories are out of scope;
  `ast` has no equivalent there.
- **Network behind an abstraction is missed.** Two known: FastMCP's
  `play_media` and `save_media` reach the network through an MCP client
  library rather than an HTTP module.
- **Call-following is bounded at three levels**, and attribution at one. A
  write four hops down is missed. That bound is why the git `commit` false
  positive survives: its `unlink` is one hop away.
- **Four codebases is not a population.** These are reference implementations
  and examples, which are likely *better* annotated than average. The
  25-of-289 annotation rate should be read as a ceiling, not a mean.
- **No runtime verification.** Everything is static. A tool that fetches its
  behaviour at runtime is invisible.

---

## 6. Why this is an authorization problem

The detector exists because of what you do with the answer.

An agent with tools is an API whose caller can be talked into anything.
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
is BOLA and BFLA with a persuadable client. You cannot patch prompt injection
out of a model, so the control belongs where it has always belonged for APIs:
at the authorization boundary, which does not trust the caller.

MCP's own authorization is explicit about its scope — it "provides
authorization capabilities at the transport level". That answers *may this
client connect to this server*. It does not answer *may this principal invoke
this tool with these arguments*, which is the question that decides whether
one user reads another's data. **MCP authorizes the connection, not the call.**

The repository closes that loop:

```
detector  ->  policy scaffold  ->  human adds constraints  ->  gate enforces
                                                           ->  attacks score it
```

The scaffold is deny-by-default with every rule commented out. It grants
nothing until somebody reads it, because a generated policy that worked out of
the box would look like coverage while enforcing whatever the generator
guessed.

Scored with a control arm: **11 of 11 attacks blocked, 0 of 4 legitimate calls
broken.** Both halves are published, because a block rate alone is
unfalsifiable — my first run scored a perfect 1.000 against a policy that
denied all file access, and only the legitimate-traffic cases caught it.

---

## Reproducing this

```bash
git clone https://github.com/gl1tchdust/agent-tool-authz
cd agent-tool-authz
pip install -r requirements.txt

./detector/fetch_corpus.sh      # pinned commits
python -m detector.measure      # re-derives 0.800 / 0.667
```

Labels are in [`detector/labels/mcp-corpus.yml`](detector/labels/mcp-corpus.yml),
one entry per finding with a verdict and the reasoning. If a label is wrong,
that file is the thing to argue with.

---

MIT licensed. Shivam Mahajan ·
[LinkedIn](https://linkedin.com/in/shivam-mahajan-a8005a205)
