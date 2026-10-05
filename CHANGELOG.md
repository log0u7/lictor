# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- The engagement flow without flags: `lictor acquire <name>` resolves the source from the target's registry entry (the `--from`/`--bin` recorded at `target add`) - one `target add` and the acquire needs no flags; the explicit flags still override.

- The ROP chaineur: the build layout gains the `chain` slot - one arch-width word per
  reference, resolved in order against the facts (`gadget:TYPE`, `plt_addr:NAME`,
  `got_addr:NAME`, `win`, `leak:NAME`, `const:N`), loud BuildError on any missing piece.
  `ret2plt` (the puts@got leak chain) and `ret2libc` (post-leak: ret-align + pop_rdi +
  binsh + system) ship as built-in layouts; a pack's `build:` teaches chains for its own
  techniques.
- `Lictor::Tube`: the ONE TCP implementation behind the banner readers (ADR 0001) -
  connect, read_until (EOF/reset/deadline/limit), write, reset tracking. `harvest` and
  `verify` consume it; `verify` honours `--facts` (it used to append to a hardcoded
  `target.facts` in the CWD, ignoring the flag).
- The success oracle reads the FLAG, not the exit code: `run --flag-regex RE` makes the
  flag pattern in the runner's output the success semantics (a polite exploit exits 0 on
  failure, a caught-cleanup exploit exits non-zero after landing the flag - the exit code
  lies both ways). Without the regex the exit code stays the oracle, the honest weaker
  fallback.
- The two-steps state: the run's leak capture - the service's own output hex addresses
  become `leaked_address` facts for the NEXT attempt (trailed as `leak` events), so a
  leak technique followed by a rebuild technique resolves its `leak:NAME` refs from the
  observed values. The boundary stays documented: a leak and its strike inside ONE
  connection is the operator's exploit craft (the scaffold pattern), not the loop's.
- The run manifest + resume (ADR 0003): one stable run id per logical run - every trail
  event carries it, the CLI prints it with the resume hint; the state (facts with the
  merged leaks, the attempt history) lands on disk per attempt (`run.json` in the target
  dir); `lictor run --resume <id>` continues THAT run - an interruption is a pause, not
  an orphan.
- Named targets (ADR 0003): `lictor target add <name> <host:port> [--from URL | --bin
  PATH]` scaffolds `targets/<name>/` (facts, payloads, its own trail) and registers it
  in `targets.yml`; `--target NAME` scopes acquire/plan/build/run/fuzz/verify/harvest
  state into the dir - the CWD-global `target.facts` clobbering is dead, two targets
  coexist.
- Per-target priors: the isolation comes from the scoped trail (the `--target` trail
  file IS the scope) - a failure on target A shifts A's decisions, B stays at the
  defaults; proven by the isolation spec.
- `lictor report --defender`: the blue-side view of the SAME trail - the raw action
  timeline (the scans, the banners read, the payloads sent, the techniques attempted
  with their verdicts) plus, per attempted technique, the pack's `detection:` hints.
- The hardening matrix in the lab: the same sources compiled canary+PIE+full-RELRO+
  FORTIFY, served on the 889x ports; `lab/purple.sh` replays the purple loop - `augure
  coverage` flips against the corpus, `lictor report --defender` reads an attack trail.
- The lab gains the missing targets: `uaf_heap` (9995, tcache UAF with the fn pointer
  on the heap - the 8 heap packs finally have a bench) and `orw` (9994, seccomp filter:
  execve dies). The builder is seccomp-aware: a `sh` stub under `seccomp("true")` is a
  booby trap, so the slot switches to the orw chain (open/read/write, clean exit) with
  the flag path embedded. The `orw` technique ships as a built-in layout.
- ADRs: docs/adr/ records the architectural decisions - the Tube as the transport seam
  (0001), verify as the arithmetic check with SMT a seam not a promise (0002),
  engagement state as a directory per target, no database (0003).

### Changed

- The report carries the WHOLE trail: `Trail#runs` maps acquire, build (offset, ret
  source, size), scaffold, harvest, verify, suggest, leak and fuzz - the auditable
  deliverable no longer omits most of the audit. `report --json` renders the same
  completeness.
- The lab is six targets (+3 hardened mirrors); the demo walks suggest-then-decide for
  the source knowledge (heap class, seccomp filter, controlled format) and
  harvest-then-build for the orw chain.
- The capabilities table documents the new surfaces: the chain-slot build, the suggest
  `-o` write-back, `harvest --facts`, the `run --flag-regex` oracle and the leak capture.

### Fixed

- `suggest` and `harvest` never persisted their results: the merged fact base was
  printed then dropped (the docs even claimed the tool "merges into the base"), and the
  harvest's leaked addresses existed only on stdout - the agent-enrichment loop was a
  dry-run simulator. `suggest -o PATH` writes the merged base, `harvest --facts PATH`
  appends the leaked_address facts; regression-tested with a fake banner server.
- The safe default poisoned the learning: a handoff attempt (manual executor, nothing
  executed) was recorded as `success: false`, and `Priors.from_trail` counted it - every
  handoff-only run systematically downgraded the decided technique for all future
  decisions. The outcome is trailed only when something actually ran; a handoff run
  stops after one recipe (nothing changes between attempts) with status `handoff`; a
  fresh auto-scaffold still continues the loop.
- `lictor build` never consulted pack `build:` sections: `layout_for` read packs but
  `build()` passed none, and `augure::Pack` had no `build` accessor at all (the pack DSL
  wrote a section nothing could read). Armor check 8 on the augure side validates the
  optional `build:` (own technique, slot vocabulary); the builder accepts `packs:` and
  the CLI passes the loaded packs. A pack teaching a NEW technique now materializes its
  own layout.
- The `dword` slot packed with the arch width (8 bytes on x64): a partial-overwrite
  layout emitted the wrong payload. `dword` is 4 bytes whatever the arch; `qword` is the
  pointer width.
- One auto-scaffold per technique per run: the loop continued on a fresh scaffold (the
  next attempt discovers it) but re-scaffolded the SAME technique on every further
  attempt, hitting the scaffold's already-exists refusal.
- The executor timeout kills a black-holed runner instead of hanging forever.

## [0.3.0] - 2026-10-04

### Changed

- **v0.3.0: the operator is the authorization.** The gates and the consent tokens are
  GONE - no allowlist file, no tokens, no typed confirmations (the review caught `run`
  minting its own consent with the target as its own confirmation). The README carries
  the authorized-use disclaimer; the trail is the record. `lictor init` scaffolds the
  trail only; the doctor checks the environment only (gdb/ronin/docker as warns with
  exact fixes).
- v0.3.0 in the gem: the operator-is-the-authorization model (consent and the allowlist
  are gone, the trail is the record), the gemspecs say so, the gem ships the build
  layouts and the scaffold template (`gem build` no longer produces a dead artifact),
  `Unauthorized` is deleted.
- The demo and every doc reflect the current commands: the harvest act replaces the
  consent act, the chain is scan → acquire → suggest → harvest → plan → build → run →
  outcome → report.

### Removed

- The consent system and the allowlist (the operator is the authorization; the trail is
  the record). The gate-era `-a`/targets.yml spec residue went with them.
- The dead empty `begin` in the plan command and the MCP's six `Unauthorized` rescues
  (the class is gone).

### Fixed

- The trail of offensive operations was world-readable: `record` now creates the JSONL
  0600 (existing files keep the operator's perms). The profiler and acquire subprocesses
  hang forever on a wedged binary: both carry a 300 s timeout raising a loud error.
- `lictor acquire` surfaces the profiler's stderr in the failure message (the profiling
  subprocess used to die silently and the error said nothing).
- The gemspecs build identically from any working directory: `files` globs anchor to
  `__dir__` and lictor-mcp reads its version from `lib/lictor-mcp/version.rb`.
- `lictor run` failure is truthful now: the lab exploit raises when the flag does not
  come, so ronin's exit code can no longer lie about the success (the `--flag-regex`
  oracle supersedes even this).

## [0.2.0] - 2026-10-03

- `lictor plan <binary>`: ELF magic detection profiles the binary
  through the augure-profile subprocess (trailed), then decides. A
  `.facts` file passes through unchanged. One command from binary to
  decision.
- `lictor scan`: nmap as a gated, trailed action against an allowlisted
  host (subprocess; --nmap override for testing). Scans appear in
  `runs` and in the engagement report.
- Network facts: service/software_version/remote emitted from nmap
  scans; remote technique packs match them like binary facts.
- Fuzzing and triage (augure-profiler): RubyMutator built-in + radamsa
  optional; GdbBackend (real run covered), RizinBackend, LldbBackend;
  `lictor fuzz` gated and trailed.
- Executor interface: ManualExecutor (default, handoff) + RoninExecutor
  (discovery from the operator's repos; fabricated names refused).
- `lictor run`: the closed loop - decide, execute, outcome, re-decide -
  with budgets and interactive confirmation.
- Consent tokens: `lictor authorize <target>` - human-typed, TTL'd,
  trail-recorded.
- lictor-mcp (4th gem): scan/plan/execute/validate_pack tools with
  server-side gates and token validation.
- `lictor rule validate|install|list`: teach augure techniques as data
  (packs), full armor + corpus guard.

### Removed

- `--i-am-authorized` and `--target` flags: security theater. A flag
  can be typed by reflex, by a script, or by anyone with shell access -
  it proves nothing and taxes the legitimate user. Authorization is the
  allowlist artifact (explicit host[:port] entries, colon-delimited
  prefix match so .1 cannot pass for .10) plus the trail. A future
  execute command will confirm interactively (show the recipe, type the
  target), never through a flag.

## [0.1.0] - 2026-10-02

- Project scaffold: authorization gates design, handoff-default README,
  CI (gitleaks), MIT license, AGENTS.md.
- Gates: explicit allowlist (wildcards rejected), per-run consent flag,
  allowlist-checked `--target`.
- Recon: nmap XML to target inventory via ruby-nmap; `lictor recon`
  prints allowlist candidates (candidates, never authorization).
- Handoff default: augure decision printed as a ronin-exploits recipe
  with mixin hints (Binary / FormatString); exploit names deferred to
  the operator's ronin repos.
- The closed loop: `lictor outcome` records results, outcomes feed the
  augure bandit priors (`Lictor::Priors.from_trail`), the next decision
  adapts - end to end trailed.
- JSONL trail with run aggregation (`lictor runs`).
- Engagement report: auditable markdown (decision, rule provenance,
  outcome) with the claims-discipline line; `lictor report -o`.
