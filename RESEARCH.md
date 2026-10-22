# Nobody is checking whether MCP tools do what they say

**Shivam Mahajan** · October 2026 · [gl1tchdust/agent-tool-authz](https://github.com/gl1tchdust/agent-tool-authz)

MCP tools declare their own risk profile. Agents read those declarations to
decide what to run without asking a human. The specification says the
declarations are untrusted and offers no way to check them, and the scanners
built for MCP do not check them either.

I built something that does and measured it twice. Once against 289 tools in
four reference codebases where every finding is hand-labelled, giving
**precision 0.800, recall 0.667**. Then against the whole official MCP
registry: 28,028 records, 3,310 repositories, **3,786 tools**.

The census overturned the claim this writeup originally made. I reported that
8.7% of tools declare any annotation and argued that figure was "a ceiling,
not a mean". It was a floor. The real rate is **39.2%**.

Also checked in: the six bugs the two corpora found in my own detector, and a
hand-labelled random sample showing that the detector's structural check is
perfect and its two interesting semantic checks are the ones that fail.

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

### Two measurements, two kinds of evidence

Scaling the corpus does not scale the ground truth, and conflating the two
would be the easy mistake: measure more code, then keep quoting the old
precision as though it still described the new population.

So the repository keeps them apart.

- **Accuracy** stays on the four pinned codebases, where every finding carries
  a hand-written verdict in `detector/labels/mcp-corpus.yml`.
- **The annotation rate** is a census over the registry. It needs no human
  judgement, only a parse, so it covers every tool found.
- **Precision on the census** is estimated from a seeded random sample of
  findings that I read and labelled by hand. It is not inherited from the
  pinned corpus.

### What it refuses to claim

Not that a server is vulnerable. Most MCP servers are single-user local tools
where a caller-supplied path is the entire product; scoping it would break
them. The official reference servers are in the corpus and **none is reported
as insecure, because none is**.

So the output is an inventory with evidence. The only assertion is the
declared-versus-actual mismatch, because that is a contradiction *inside the
server's own manifest* and holds however it is deployed.

---

## 3. Accuracy, on labelled ground truth

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
declares nothing, which is an SSRF-shaped surface in an example file, which is
to say in code that will be copied.

**`show_map`** (FastMCP). `httpx2.get()` against a geocoding API, undeclared.
This one was *initially missed*; see §6.

### The false positive

The official git server's `commit` tool, flagged `destructive-understated`
because `git_commit()` calls `unlink()` on `.git/MERGE_HEAD` after a merge.
That is internal plumbing. A commit is additive, `destructive_hint=False` is
correct, and the scanner is wrong.

**It is left unfixed.** Narrowing the rule until this one case disappeared
would be fitting to a single example. A published 0.800 that anyone can
re-derive is worth more than a 1.000 that was tuned into existence.

---

## 4. The census, and the claim it overturned

Four codebases is not a population, so the second measurement takes the
**official MCP registry** as its sampling frame. That is a defined population
published by the people who define the protocol, rather than whatever a GitHub
code search happened to return.

The sweep ran to the genuine end: 282 pages, `ac.inference.sh/mcp` through
`zone.waggle/waggle`.

| Stage | Count |
|---|---|
| Registry records | 28,028 |
| Current active servers with a GitHub repository | 3,310 distinct repos |
| Resolved | **2,699** |
| Returned 404 | 611 |
| Unresolved | **0** |
| Containing Python | 704 |
| With statically detectable MCP tools | 209 |
| **Tools** | **3,786** |

Only `*.py` was fetched, from a tarball at a resolved commit SHA. Nothing was
cloned, installed, imported or executed, and no server in the registry was
ever contacted.

### 39.2%, not 8.7%

```
tool-level   1484 / 3786  = 0.392
repo-level     78 /  209  = 0.373
```

The earlier version of this writeup said:

> Of 289 tools, 25 declare any annotations at all. The mismatch problem is
> real but small today, because the thing being mismatched is mostly absent.

and justified treating that as an upper bound:

> These are reference implementations and examples, which are likely *better*
> annotated than average. The 25-of-289 annotation rate should be read as a
> ceiling, not a mean.

**That reasoning was exactly backwards.** SDK and FastMCP examples are minimal
teaching demos. They strip annotations out to keep the example focused, which
makes them among the *least* annotated code in the ecosystem rather than the
most. 8.7% was a floor, and the real rate is four and a half times higher.

Two checks before trusting 0.392, because a tool-level rate is precisely where
clustering hides. The largest repository alone holds 220 tools and the top ten
hold 35.9% of all of them, so one project's shared constant can move the
pooled figure. Computing the rate per repository, where each project counts
once regardless of size, gives 0.373. The two agreeing within two points is
what makes the number worth quoting.

Adoption is also bimodal rather than gradual. Of 209 repositories with tools,
**69 annotate every tool, 131 annotate none, and only 9 are partial.** It is a
convention split: either the author knows annotations exist and applies them
everywhere, usually through a shared constant, or has never encountered them.

### Why this strengthens the case rather than weakening it

The old framing was apologetic. The problem was real but small, because the
thing being mismatched was mostly absent.

That excuse is gone. **Nearly two in five tools carry declarations a client
may gate auto-approval on.** Checking whether those declarations match the
code matters four times more than the original corpus implied.

### Findings

**563 findings across 76 repositories.**

| Kind | Count | Severity |
|---|---|---|
| `undeclared-risk` | 480 | LOW |
| `closed-world-violation` | 55 | MEDIUM |
| `readonly-violation` | 22 | HIGH |
| `destructive-understated` | 6 | MEDIUM |

These are **not** labelled ground truth. 563 hand-written verdicts do not
exist, so the next section estimates precision rather than asserting it.

### A second result, checked twice

**611 of 3,310 registry entries, 18.5%, point at GitHub repositories that no
longer resolve publicly.** Eight were spot-checked at random and all eight
returned HTTP 404.

I state this only because the unresolved count came back zero. An earlier run
of the same pipeline reported 38% missing, which turned out to be my own
request rate tripping GitHub's secondary limit and being recorded as deletion.
See §6.

---

## 5. Precision by kind: the boring check works, the interesting ones do not

A random sample of 12 findings, drawn with a fixed seed from the 563, read and
labelled by hand. Verdicts and reasoning are in
[`census/labels/sample-2026-10-22.json`](census/labels/sample-2026-10-22.json).

**Precision 0.833, Wilson 95% interval [0.552, 0.953].**

The interval is wide because 12 is a small sample, and findings cluster by
repository, so the true uncertainty is wider still. The point estimate is not
the result. This is:

| Kind | Correct in sample |
|---|---|
| `undeclared-risk` | **10 / 10** |
| `closed-world-violation` | 0 / 1 |
| `readonly-violation` | 0 / 1 |

Across this sample and an earlier one I examined two findings of each
high-severity kind. **All four were false positives.**

So the mundane rule is perfect and the headline-grabbing rules are the broken
ones. That is the opposite of a result anyone would choose to publish, and the
reason is structural rather than a tuning problem.

`undeclared-risk` asks two cheap mechanical questions. Does the tool declare
anything? Does it do anything? Both are decidable from the syntax tree.

`readonly-violation` asks whether an operation "modifies the environment",
which is a semantic judgement, and the detector makes it badly:

**`drift_status`** declares `readOnlyHint=True` and was flagged for calling
`write`. The write is a telemetry line appended to a local log, whose own
docstring reads "Append a miss marker line (not-found / 0-match); never
raises. No key/value is stored (privacy)." Internal bookkeeping is not a
modification of anything the caller owns. This is the same class as the git
`MERGE_HEAD` false positive in §3.

**`get_rfo_guidance`** declares `readOnlyHint=True` and was flagged HIGH for
`asyncio.create_subprocess_exec`. The subprocesses are `curl` invoked with
`--proto =https`, `--max-filesize` and `--max-redirs 0`, and a worker module
that isolates CPU-heavy PDF and HTML parsing from the event loop. Nothing in
the caller's environment is modified. **The detector conflates spawning a
subprocess with mutating state**, and the result is that an unusually
security-conscious server gets a HIGH-severity finding for defensive
engineering. That is the worst shape a false positive can take: it penalises
the exact practice you want to encourage.

**Both `closed-world-violation` findings** were against one gateway whose
author defines five annotation constants and deliberately separates `READ_ONLY`
with `open_world_hint=False` from `READ_EXTERNAL` and `WRITE_EXTERNAL` with
`open_world_hint=True`. They chose closed-world for calls to their own fixed
service. The specification says "If false, the tool's domain of interaction is
closed", and a single known service is a closed domain. The rule "any network
call implies an open world" is too strict. This one is genuinely debatable, and
it is counted against the detector anyway.

The honest reading: **this tool is a reliable inventory of undeclared
behaviour and an unreliable judge of declared behaviour.** The first is still
worth having, because 480 of the 563 findings are that kind and nothing else
produces that inventory today. But the severity ordering is upside down, and
nothing in the output warns a reader about it.

---

## 6. Six bugs the corpora found in the detector

Everything below is a wrong answer my scanner gave against real code. Each is
now a regression test. They are worth reading because they are the ways this
class of tool fails quietly.

### Bare `.get()` is not a network call

`get` was in my network-call set. It matched `token.claims.get("sub")` in the
FastMCP auth example, producing **20 false positives** across the SDK examples
before I looked at one closely.

`.get()` is the most common method name in Python. The fix was to match HTTP
verbs only when the receiver is a module that was imported, which also fixed
`show_map`, where the receiver is `httpx2`, a package name no hardcoded list
would have contained.

### `repo.commit()` is a read

GitPython's `repo.commit(rev)` resolves a revision. `repo.index.commit()`
creates one. Matching the bare verb reported the read-only `show` tool as a
`readOnlyHint` violation.

### Attribute calls are not module functions

The worst one. Having matched `repo.commit(...)`, my interprocedural analysis
resolved the name `commit` against module-level functions, found the `commit`
**tool handler**, followed into it, and inherited its file deletions.

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
reset as `mutate state: 0`. Not a near-miss, the opposite of the truth.
Following module-local helpers, bounded at three levels, fixed it.

### `@server.call_tool()` is a dispatcher, not a tool

Found by the census. On a low-level `Server`, `@server.call_tool()` registers
the single dispatcher for *every* tool the server exposes. I had it in the
same match list as `@mcp.tool()`, so each such server contributed one phantom
tool, named after the dispatcher, taking `(name, arguments)`, carrying the
aggregated behaviour of everything the dispatcher could reach.

That was **82 phantom tools** across the registry, 65 in the largest
repository alone, from 92 files using the pattern. Because nobody annotates a
dispatcher, every phantom landed in the unannotated column and pushed the
measured annotation rate down.

Excluding it costs a real blind spot rather than a wrong answer: a server
built on the low-level API returns its tools as data from `list_tools()`, so
a static reader cannot see them and the repository honestly reports zero
tools. That is now a documented limit rather than a phantom.

### A failure recorded as data, four times over

Not a detector bug, a harness bug, and the one I would most want a reviewer to
read. Building the census I wrote four separate bugs with one shape: **a
failure that looked like a result**.

| What failed | What it looked like | Cost |
|---|---|---|
| A page read as cp1252 threw on an em dash | end of the registry | stopped at 300 of 28,028 records, exit 0 |
| `print()` emitted CRLF, `mapfile -t` kept the `\r` | every repository unreachable | 100% false miss rate |
| The API answered a valid cursor with zero rows | end of the registry | stopped at `com.m*`, a fifth of the data, exit 0 |
| GitHub's secondary rate limit | repositories deleted | **38% of the registry reported dead** |

Every one of them exited successfully and produced a plausible number. The
last was caught only by spot-checking six "deleted" repositories and finding
five alive, one of which was the MCP registry's own repository.

Had it gone unchecked, "38% of MCP registry entries point at dead
repositories" would have been published as a finding. It would have been
entirely an artefact of my own request rate.

The fixes make each failure mode loud. `pageinfo.py` exits 3 for an empty page
and the harvest rechecks the same cursor four times before accepting the end
of the data. Repository resolution returns one of three verdicts, and
`ERROR` is reported separately from `MISS`, because an unresolved repository
folded into the miss count quietly biases every rate taken from the corpus.

---

## 7. Limits

- **Python only.** A GitHub search for `mcp-server language:typescript`
  returned 48,619 repositories on 2026-10-22, all out of scope. `ast` has no
  equivalent there. That count drifts daily and depends on the query, so take
  it as an order of magnitude rather than a measurement.
- **Decorator-defined tools only.** Servers built on the low-level `Server`
  API return their tools as data from `list_tools()`, which a static reader
  cannot enumerate. 92 files in the registry use that pattern and report zero
  tools rather than wrong ones.
- **Severity is unreliable.** The HIGH and MEDIUM kinds were wrong in all four
  cases examined. Treat `undeclared-risk` as the trustworthy output and the
  rest as leads.
- **Network behind an abstraction is missed.** Two known: FastMCP's
  `play_media` and `save_media` reach the network through an MCP client
  library rather than an HTTP module.
- **Call-following is bounded at three levels**, and attribution at one. A
  write four hops down is missed. That bound is why the git `commit` false
  positive survives: its `unlink` is one hop away.
- **Census precision is an estimate from 12 findings.** The Wilson interval is
  [0.552, 0.953], and findings cluster by repository, so the real uncertainty
  is wider. It is not the 0.800 measured on labelled ground truth, and the two
  must not be quoted interchangeably.
- **The registry is not the ecosystem.** It is a defined, citable population,
  but servers that were never published to it are invisible here.
- **No runtime verification.** Everything is static. A tool that fetches its
  behaviour at runtime is invisible.

---

## 8. Why this is an authorization problem

The detector exists because of what you do with the answer.

An agent with tools is an API whose caller can be talked into anything.
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
is BOLA and BFLA with a persuadable client. You cannot patch prompt injection
out of a model, so the control belongs where it has always belonged for APIs:
at the authorization boundary, which does not trust the caller.

MCP's own authorization is explicit about its scope. It "provides
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
unfalsifiable. My first run scored a perfect 1.000 against a policy that
denied all file access, and only the legitimate-traffic cases caught it.

---

## Reproducing this

Accuracy against labelled ground truth:

```bash
git clone https://github.com/gl1tchdust/agent-tool-authz
cd agent-tool-authz
pip install -r requirements.txt

./detector/fetch_corpus.sh      # pinned commits
python -m detector.measure      # re-derives 0.800 / 0.667
```

The registry census. The harvest and fetch take a few hours and are resumable,
so rerun either after an interruption:

```bash
./census/harvest.sh                                   # pages the registry
python census/select.py .census/pages .census/candidates.json
./census/fetch.sh                                     # *.py at pinned SHAs
python -m census.census --sample 12                   # rate, findings, sample
```

Labels are in
[`detector/labels/mcp-corpus.yml`](detector/labels/mcp-corpus.yml) and
[`census/labels/sample-2026-10-22.json`](census/labels/sample-2026-10-22.json),
one entry per finding with a verdict and the reasoning. If a label is wrong,
those files are the thing to argue with.

The registry moves. A census run on a later date will not reproduce 28,028
records or 3,786 tools, which is why the figures here name the date and the
pipeline is checked in.

---

MIT licensed. Shivam Mahajan ·
[LinkedIn](https://linkedin.com/in/shivam-mahajan-a8005a205)
