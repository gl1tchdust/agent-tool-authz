#!/usr/bin/env python3
"""Score a policy against the attack suite.

    python -m benchmark.run --cases attacks/cases.yml --policy attacks/policy.yml

Runs every case twice. Once through a gate with no policy, which establishes
that the attack works at all, and once through the policy under test.

Both numbers are reported, because only one of them is interesting on its own
and it is not the one people quote. "The gate blocked 12 attacks" is
unfalsifiable without knowing how many of those 12 would have succeeded
unguarded. The control arm is what turns it into a measurement.

The suite contains legitimate calls as well as attacks, marked
`attacker_wins_when: denied`. Without them a policy of "deny everything"
scores a perfect block rate, which is how security controls get shipped that
nobody can work with. Those cases are reported separately as breakage.

Exit codes:
    0  every attack blocked and no legitimate call broken
    1  at least one attack succeeded, or a legitimate call was refused
    2  could not run: bad cases file, bad policy
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from src.gate import Gate, open_gate  # noqa: E402
from src.normalize import Principal, ToolCall  # noqa: E402
from src.policy import Policy, PolicyError  # noqa: E402


@dataclasses.dataclass
class CaseResult:
    id: str
    title: str
    severity: str
    owasp: str
    is_attack: bool          # False for the legitimate-traffic controls
    succeeded_unguarded: bool
    succeeded_guarded: bool
    rule_id: str | None
    reason: str

    @property
    def blocked(self) -> bool:
        return self.is_attack and self.succeeded_unguarded and not self.succeeded_guarded

    @property
    def missed(self) -> bool:
        return self.is_attack and self.succeeded_guarded

    @property
    def broken(self) -> bool:
        """A legitimate call the policy refused."""
        return not self.is_attack and not self.succeeded_guarded


def build_principals(scenario: dict) -> dict[str, Principal]:
    out = {}
    for name, spec in (scenario.get("principals") or {}).items():
        spec = spec or {}
        if name == "anonymous" and not spec.get("roles"):
            out[name] = Principal.anonymous()
            continue
        out[name] = Principal(
            id=name,
            roles=frozenset(spec.get("roles") or ()),
            attributes=dict(spec.get("attributes") or {}),
        )
    return out


def run(cases_path: pathlib.Path, policy_path: pathlib.Path) -> tuple[list[CaseResult], dict]:
    doc = yaml.safe_load(cases_path.read_text(encoding="utf-8")) or {}
    scenario = doc.get("scenario") or {}
    principals = build_principals(scenario)
    policy = Policy.from_file(policy_path)

    # Neither gate executes anything: the question is whether the call would
    # be permitted, and running the tool to find out would be a poor way to
    # test a delete.
    never_executes = lambda call: None  # noqa: E731
    guarded = Gate(policy, never_executes)
    control = open_gate(never_executes)

    results: list[CaseResult] = []
    for case in doc.get("cases") or []:
        who = case.get("as")
        if who not in principals:
            raise PolicyError(f"case {case['id']}: unknown principal {who!r}")

        spec = case.get("call") or {}
        call = ToolCall(
            tool=spec.get("tool", ""),
            arguments=dict(spec.get("arguments") or {}),
            principal=principals[who],
        )

        wins_when = case.get("attacker_wins_when", "allowed")
        if wins_when not in ("allowed", "denied"):
            raise PolicyError(f"case {case['id']}: attacker_wins_when must be allowed or denied")

        unguarded = control.check(call)
        decision = guarded.check(call)

        results.append(CaseResult(
            id=case["id"],
            title=case.get("title", ""),
            severity=str(case.get("severity", "-")),
            owasp=str(case.get("owasp", "-")),
            is_attack=(wins_when == "allowed"),
            succeeded_unguarded=unguarded.allowed,
            succeeded_guarded=decision.allowed,
            rule_id=decision.rule_id,
            reason=decision.reason,
        ))

    attacks = [r for r in results if r.is_attack]
    legit = [r for r in results if not r.is_attack]
    blocked = [r for r in attacks if r.blocked]
    missed = [r for r in attacks if r.missed]
    broken = [r for r in legit if r.broken]

    stats = {
        "attacks": len(attacks),
        "succeeded_unguarded": sum(1 for r in attacks if r.succeeded_unguarded),
        "blocked": len(blocked),
        "missed": len(missed),
        "block_rate": round(len(blocked) / len(attacks), 4) if attacks else 0.0,
        "legitimate_calls": len(legit),
        "broken": len(broken),
        "breakage_rate": round(len(broken) / len(legit), 4) if legit else 0.0,
    }
    return results, stats


def report(results: list[CaseResult], stats: dict) -> str:
    lines = []
    width = max((len(r.id) for r in results), default=8)

    lines.append("attack suite")
    lines.append(f"  {'case'.ljust(width)}  unguarded  guarded   verdict")
    lines.append(f"  {'-' * width}  ---------  -------   -------")
    for r in results:
        if not r.is_attack:
            continue
        verdict = "BLOCKED" if r.blocked else ("MISSED" if r.missed else "never worked")
        lines.append(
            f"  {r.id.ljust(width)}  {'succeeds' if r.succeeded_unguarded else '  fails ':<9}  "
            f"{'succeeds' if r.succeeded_guarded else 'denied  ':<8}  {verdict}"
        )

    lines.append("")
    lines.append("legitimate traffic (must keep working)")
    for r in results:
        if r.is_attack:
            continue
        lines.append(f"  {r.id.ljust(width)}  {'BROKEN' if r.broken else 'ok'}    {r.title}")

    lines.append("")
    lines.append(f"attacks            {stats['attacks']}")
    lines.append(f"  work unguarded   {stats['succeeded_unguarded']}")
    lines.append(f"  blocked          {stats['blocked']}")
    lines.append(f"  missed           {stats['missed']}")
    lines.append(f"  block rate       {stats['block_rate']:.3f}")
    lines.append("")
    lines.append(f"legitimate calls   {stats['legitimate_calls']}")
    lines.append(f"  broken           {stats['broken']}")
    lines.append(f"  breakage rate    {stats['breakage_rate']:.3f}")

    missed = [r for r in results if r.missed]
    if missed:
        lines.append("")
        lines.append("--- attacks that got through ---")
        for r in missed:
            lines.append(f"  {r.id}  {r.severity:<9} {r.title}")
            lines.append(f"      allowed by: {r.rule_id} - {r.reason[:110]}")

    broken = [r for r in results if r.broken]
    if broken:
        lines.append("")
        lines.append("--- legitimate calls the policy refused ---")
        for r in broken:
            lines.append(f"  {r.id}  {r.title}")
            lines.append(f"      {r.reason[:110]}")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Score a policy against the attack suite.")
    ap.add_argument("--cases", type=pathlib.Path, default=pathlib.Path("attacks/cases.yml"))
    ap.add_argument("--policy", type=pathlib.Path, default=pathlib.Path("attacks/policy.yml"))
    ap.add_argument("--json-out", type=pathlib.Path, default=None)
    args = ap.parse_args()

    for path in (args.cases, args.policy):
        if not path.exists():
            print(f"::error::not found: {path}", file=sys.stderr)
            return 2

    try:
        results, stats = run(args.cases, args.policy)
    except PolicyError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    print(report(results, stats))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({
            "stats": stats,
            "cases": [dataclasses.asdict(r) for r in results],
        }, indent=2), encoding="utf-8")

    if stats["missed"] or stats["broken"]:
        print(f"\n::error::{stats['missed']} attack(s) got through, "
              f"{stats['broken']} legitimate call(s) broken")
        return 1

    print("\nevery attack blocked, no legitimate call broken")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
