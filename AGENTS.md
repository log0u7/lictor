# AGENTS.md (lictor)

## Project

lictor: authorized-ops orchestrator consuming the augure gem. SCAFFOLD
STAGE - design docs only until augure is stable.

## Hard rules (enforced in code, in review, everywhere)

1. Every operational mode requires an explicit target allowlist file.
   No allowlist -> `Lictor::Unauthorized`. No defaults, no wildcards.
2. Automated execution (RPC mode) requires `--i-am-authorized` per run.
3. Handoff mode (print the msfconsole recipe) is the default and must stay
   the default in every design and test.
4. Every action logs decision -> rule -> module -> outcome (sequel).
5. Lictor never decides technique selection; it consumes augure.
6. No exploit code, no payload generation - orchestration of standard
   tooling only (nmap, msfrpcd).

## Workflow

Same as augure: TDD first, conventional commits (English, atomic),
CHANGELOG [Unreleased] per change, SemVer 0.x, main stays green. Ruby 3.4+
via mise. No PR/review required during bootstrap (single author); PRs with
review become the rule once a second contributor lands.
