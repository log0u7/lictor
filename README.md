# lictor

![lictor - the fasces of fiber, the trail behind, the open door ahead](docs/art/lictor-v1.png)

**The orchestrator that carries out augure's judgments: nmap, fuzzing,
profiling, execution - every action recorded, handoff by default.**

> *Lictor (n.): the magistrate's attendant who carried the fasces and
> executed judgments. He did not judge. He executed what was judged.*

[![CI](https://github.com/log0u7/lictor/actions/workflows/ci.yml/badge.svg)](https://github.com/log0u7/lictor/actions/workflows/ci.yml)
[![Ruby](https://img.shields.io/badge/ruby-%3E%3D%203.4-ruby.svg)](https://www.ruby-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**v0.3.0** - pairs with [augure](https://github.com/log0u7/augure), the
auditable exploitation decision layer. augure decides; lictor executes;
the trail records everything.

> **Authorized use only.** This tool is for legally authorized security
> assessments and CTF labs. You are the operator: what it does, you
> did. Know the law where you stand.

## Why lictor

Most automation in offensive tooling is a black box: it fires and you
find out why afterwards - or never. lictor inverts that:

- every technique choice comes from a **verified rule with its
  evidence** (augure's explain payload: rule ID, facts, seeded draw);
- every action is **trailed** - one JSONL line, attributable, replayable;
- the dangerous edge - execution - is opt-in: the default executor is
  the handoff, which prints the recipe and runs nothing.
- the mirror is the analysis target: the scan identifies, the local
  reproduction gets profiled and built against, `verify` proves the
  remote faults like the local model.

Equally strict when an LLM agent drives it through MCP. The brakes are
not a mode - they are the design.

## The 60-second demo

![lictor demo: scan, decide with provenance, run, and the auditable trail](docs/art/demo.gif)

Replay it yourself against the lab:

```sh
sh lab/demo.sh
```

The full chain is: **scan → mirror → (fuzz → triage) → verify →
suggest → plan → build → run → outcome → report** - every step is
recorded in the trail, the decision is explained rule-by-rule.
`suggest` is the agent's own step: propose observations as facts, get
the decision delta back
(see [docs/how-to-llm-suggestions.md](docs/how-to-llm-suggestions.md));
`build` is the payload step: the offset is measured, the bytes are
assembled (below). When discovery finds NO exploit for the decided
technique, the run scaffolds it and the next attempt uses it; when NO
technique applies to the crash, `lictor draft` writes a staged pack
from the observations - the loop feeds augure back.

## From decision to payload: the offset is measured, not guessed

The original tool this project descends from ended with a payload: the
padding, the return address, the shellcode. `lictor build` carries that
inheritance - with every number auditable instead of assumed:

- the **offset is measured**: a cyclic pattern crashes the acquired
  binary under the debugger; the instruction pointer (or the rbp slot a
  `leave; ret` epilogue betrays) pins the exact offset back in the
  pattern. No brute-force loop, no magic constant.
- the **return address comes from the facts**: the profiler keeps the
  winning symbol's name and address (`win_symbol`), or the classic
  `ff e4` - named for the target's stack register (`jmp_rsp`/`jmp_esp`).
- the **shellcode is assembly source**: readable, versioned stubs
  (execve /bin/sh, execve /bin/bash -p) assembled on demand by metasm -
  no hex blobs, no external generator.
- the result is a payload file the trail records and `lictor run
  --payload` sends as-is. When the flag does not come, the exploit says
  so and the run says failed.

```sh
lictor build ret2func --facts target.facts -o payload.bin
# technique:  ret2func
# offset:     16  (measured: cyclic pattern under the debugger)
# ret:        win_symbol:win@4198870
# payload:    payload.bin (24 bytes, arch x64)
lictor run 127.0.0.1:9999 --facts target.facts \
  --executor ronin --payload payload.bin
```

## Capabilities

| Command | What it does |
|---|---|
| `init` / `doctor` | Scaffold the engagement setup; verify the environment (exact fix per check). |
| `scan <host>` | nmap against a target; the scan is recorded. |
| `acquire <target>` | The lab convenience: copy or download the binary when the target serves it. The real flow is the MIRROR (below). |
| `fuzz <binary>` | Fuzz + triage a local binary: the fact **discovery** layer. Length sweep + mutations; gdb/rizin/lldb backends. |
| `verify <target>` | The differential: the crash input faults the remote like the local model → the facts become `remote-verified`. |
| `plan <binary-or-facts>` | Profile if ELF, decide (augure), print the recipe. |
| `build <binary>` | Assemble the payload for the selected technique: measured offset (cyclic pattern under the debugger), fact-sourced return address, metasm-assembled shellcode. |
| `suggest <facts>` | The agent proposes observations as facts; augure re-decides and the delta comes back. |
| `draft <facts>` | No technique applies? The observed facts + the measured constants draft a PACK in the staging dir, armor-validated, for the operator to review and install. |
| `exploit scaffold <technique>` | Draft the ronin exploit for a decided technique: the measured constants embedded, the payload loader wired - review, commit, run. |
| `run <target>` | The closed loop: decide, execute, outcome, re-decide - with an attempt budget. |
| `outcome <run-id>` | Record the result; the next decision adapts the priors. |
| `report` | The auditable engagement report (markdown, provenance included). |
| `rule validate/install/list` | Teach augure a new technique - as data, through the armor. |

## The operator is the authorization

No gates, no tokens. You decide what to target; the trail records what
was done:

1. **Handoff is the default.** `plan` prints the recipe and executes
   nothing; `run` with the ronin executor is opt-in and budgeted.
2. **The trail is append-only.** Decision → rule provenance → action →
   outcome. An engagement you cannot replay is an engagement you cannot
   defend.
3. **The mirror is the analysis target.** The scan identifies
   (service + version); when the remote cannot be profiled, you stand
   up the SAME service locally - your package, your install - and
   lictor scans+profiles the mirror, builds on its facts, and `verify`
   proves the remote faults like the local model before anything runs
   for real.

## Architecture

```mermaid
flowchart LR
    subgraph recon ["RECON - ruby-nmap 1.0.3"]
        NMAP["nmap -sV -oX scan.xml<br/>(operator-run)"] --> R["Lictor::Recon<br/>(parses XML, never scans)"]
        R --> INV["target inventory<br/>+ service/version facts"]
    end

    INV -- "service facts drive the match" --> A

    subgraph decide ["DECIDE - the augure SDK"]
        ELF["target binary"] --> PRF["augure-profiler<br/>metasm: checksec, gadgets"]
        PRF --> F["facts<br/>nx/pie/plt/gadget/vuln_hint"]
        F --> A["augure Engine<br/>Datalog rules-as-data"]
        KB["KnowledgeBase<br/>22 patterns"] -. priors .-> A
        A --> V["Verifier + Bandit + MCTS"]
        V --> D["decision + provenance<br/>rule ID, evidence, seed"]
    end

    subgraph act ["ACT - lictor (Ruby-native arsenal)"]
        D -- "handoff (default)" --> H["recipe printed<br/>ronin mixin + technique"]
        D -- "opt-in, budgeted" --> RN["ronin-exploits<br/>+ rex gems<br/>gem install, no daemon"]
        H --> O["outcome"]
        RN --> O
    end

    O --> TR["JSONL trail<br/>decision - rule - module - outcome"]
    O -. "closed loop: outcomes become facts" .-> F
```

## The Ruby-native arsenal

| Need | Gem | Why |
|---|---|---|
| nmap XML parsing | [ruby-nmap 1.0.3](https://rubygems.org/gems/ruby-nmap) (postmodern, 703k dl) | the maintained standard; parses XML without running nmap |
| exploitation runtime | [ronin-exploits 1.1.1](https://rubygems.org/gems/ronin-exploits) + [ronin 2.1.1](https://rubygems.org/gems/ronin) | exploits as Ruby classes, mixins = the technique vocabulary; no daemon, `gem install` |
| primitives | [rex-bin_tools](https://rubygems.org/gems/rex-bin_tools), [rex-arch](https://rubygems.org/gems/rex-arch), [rex-socket](https://rubygems.org/gems/rex-socket) (Rapid7, 2026-maintained) | msf's Ruby internals gemified: ELF/ROP, assembly, raw sockets |
| binary analysis | `augure-profiler` (metasm) | pure Ruby, no subprocess, augure's sibling gem |
| fuzzing | built-in `RubyMutator` (zero-dep) + radamsa optional | the discovery layer for binaries with no write-up |
| persistence | stdlib JSONL | sequel when queries are actually needed |

**Why not Metasploit?** It IS Ruby - but a monolithic Rapid7 app you
must install and drive through a dead RPC gem. `ronin` + `rex` install
as gems and carry the same primitives natively. Metasploit remains an
optional module arsenal behind msfrpcd when a specific ready-made
module is worth the install - but it is not on lictor's critical path.

## The MCP surface: when an LLM agent drives

[lictor-mcp](mcp_server/) exposes seven tools over stdio - `scan_target`,
`plan_technique`, `execute_technique`, `suggest_facts`, `build_payload`,
`scaffold_exploit`, `validate_pack` -
and validates
**server-side**: the armor, the corpus guard, the trail.
The agent proposes; augure disposes; lictor executes - and the checks
run server-side, so the agent cannot weaken them. Agents teach augure new techniques through the same armor:
see [augure's pack format](https://github.com/log0u7/augure/blob/main/docs/pack-format.md)
and the [augure-operator skill](https://github.com/log0u7/augure/tree/main/skills/augure-operator).

## Honest numbers

Read every claim below as a **prediction with provenance**, not a field
result - the lab is the measurement bench, not the world:

| Claim | Evidence |
|---|---|
| ret2func: the built payload lands the real flag, no brute-force | the lab, e2e: build (offset 16 measured) → run → `FLAG{augure_decides_lictor_executes}` |
| the offset measurement generalizes | static frame read (ret2win x64 = 40, the canonical number) + the cyclic pattern under the debugger, cross-validated on the same binaries |
| a missing exploit drafts itself | the run's auto-scaffold: discovery empty + binary in hand -> the exploit file lands in the repo, the next attempt uses it |
| an unknown crash becomes a pack | `lictor draft`: the observed facts + the measured constants -> an armor-validated pack in the staging dir |
| corpus: 33/33 technique classifications | `augure-benchmark`, CI-enforced at 100% |
| shellcode / ret2plt / fmtstr targets | fact bases + recipes shipped; the build templates and verified runs are the next lab mile |

A run that fails says failed: the lab exploit raises when the flag does
not come, so the exit code cannot mask a miss.

## Acceptable use

Lictor exists for **authorized security work** (you are responsible for the legality where you stand): engagements with a
signed scope, labs you own, CTF environments. The authorization model
is load-bearing; bypassing it is the one contribution that will be
rejected on sight. Lictor writes no exploit code - it orchestrates the
operator's chosen tooling; the knowledge lives in the repos, not here.

## Install

Lictor is distributed as a source checkout for a reason: an orchestrator
around pentest tooling has no business being one `gem install` away
from anyone. Bundle it from this repo:

```ruby
# Gemfile
gem "augure"                       # published, clean, MIT
# lictor + lictor-mcp: bundle from your own checkout, private
```

## Documentation

| I want to... | Read |
|---|---|
| run the demo end to end | [the lab](lab/README.md) |
| understand the operator model | [the operator section](#the-operator-is-the-authorization) |
| see what augure decides and why | [augure's README](https://github.com/log0u7/augure) |
| write the auditability story | [augure's auditability page](https://github.com/log0u7/augure/blob/main/docs/auditability.md) |
| teach augure a technique | [the pack format](https://github.com/log0u7/augure/blob/main/docs/pack-format.md) |

## License

MIT, same as augure.
