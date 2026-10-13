# AGENTS.md (lictor)

## Project

lictor: the orchestrator that carries out augure's judgments - v0.3.0+
ships: scan/acquire (ruby-nmap, the mirror), fuzzing/triage
(augure-profiler), harvest, verify, suggest, handoff + ronin
execution, the closed loop (outcome -> priors), JSONL trail (0600),
the build layer (measured offset, the ROP chaineur, pack layouts,
the seccomp-aware orw switch), named targets (target add/--target,
the engagement model, ADR 0003), the run manifest + resume, the leak
capture, the flag-regex oracle, engagement reports (+ the defender
view), the MCP surface (lictor-mcp) and the six-target lab with the
hardening matrix + purple.sh. The operator is the authorization.

## Hard rules (enforced in code, in review, everywhere)

1. The OPERATOR is the authorization. No gates, no tokens, no allowlist
   file - all removed as friction that proves nothing (a flag or a file
   can be written by anything with shell access). The trail is the
   record; the README carries the authorized-use disclaimer.
2. Handoff (print the recipe) is the default; `plan` executes nothing.
3. Every action is trailed: decision -> rule provenance -> recipe ->
   outcome (JSONL; sequel when queries are actually needed).
4. Lictor never decides technique selection; it consumes augure.
   Outcomes feed back through `Lictor::Priors.from_trail`, never by
   touching augure's internals.
5. No exploit CODE: the exploits live in the operator's ronin repos;
   lictor orchestrates them. The payload assembly (`lictor build`) is
   measurement, not invention: the offset is measured under the
   debugger, the return address comes from the facts, the shellcode
   stubs are committed assembly source. The exploit NAME always comes
   from the operator's ronin repos.

## Commands

- Test: `bundle exec rspec` (all green required, 124 examples)
- Lint: `bundle exec standardrb` (zero offenses required)
- CLI: `bundle exec ruby bin/lictor --help`

## Workflow

Same as augure: TDD first, conventional commits (English, atomic),
CHANGELOG [Unreleased] per change, SemVer 0.x, main stays green. Ruby 3.4+
via mise. `main` is protected (repository ruleset): every change lands
through a pull request - see `CONTRIBUTING.md`.

## Gotchas

- augure resolves from `../augure` locally, `./augure` in CI (the Gemfile
  picks whichever exists; no Gemfile.lock, it is path-dependent).
- Trail JSON round-trips symbol keys to strings: Trail#runs and
  Lictor::Report normalize for that.
- The msfconsole-era tests were migrated; anything mentioning msfrpcd in
  code is a regression - it is an optional arsenal, not the path.
