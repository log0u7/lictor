# AGENTS.md (lictor)

## Project

lictor: authorized-ops orchestrator consuming the augure gem. v1 shipped:
gates, recon (ruby-nmap), handoff (ronin-first recipes), outcome feedback
(the closed loop), JSONL trail, engagement reports.

## Hard rules (enforced in code, in review, everywhere)

1. Authorization = the allowlist artifact: explicit host[:port] entries,
   written and versioned by the operator. Wildcards structurally rejected.
   No target outside the file - ever.
2. NO consent flag. It was removed as security theater: a flag can be
   typed by reflex, by a script, or by anyone with shell access. The
   controls are the artifact and the trail. A future execute command
   confirms interactively (show the recipe, type the target) - never a
   flag.
3. Handoff (print the recipe) is the default; `plan` executes nothing,
   so it needs no more than a valid allowlist file.
4. Every action is trailed: decision -> rule provenance -> recipe ->
   outcome (JSONL; sequel when queries are actually needed).
5. Lictor never decides technique selection; it consumes augure.
   Outcomes feed back through `Lictor::Priors.from_trail`, never by
   touching augure's internals.
6. No exploit code, no payload generation - orchestration of the
   Ruby-native arsenal (ronin-exploits + rex gems) only. The exploit
   NAME always comes from the operator's ronin repos.

6. No exploit code, no payload generation - orchestration of the
   Ruby-native arsenal (ronin-exploits + rex gems) only. The exploit
   NAME always comes from the operator's ronin repos.

## Commands

- Test: `bundle exec rspec` (all green required, 40+ examples)
- Lint: `bundle exec standardrb` (zero offenses required)
- CLI: `bundle exec ruby bin/lictor --help`

## Workflow

Same as augure: TDD first, conventional commits (English, atomic),
CHANGELOG [Unreleased] per change, SemVer 0.x, main stays green. Ruby 3.4+
via mise. No PR/review required during bootstrap (single author); PRs with
review become the rule once a second contributor lands.

## Gotchas

- augure resolves from `../augure` locally, `./augure` in CI (the Gemfile
  picks whichever exists; no Gemfile.lock, it is path-dependent).
- Trail JSON round-trips symbol keys to strings: Trail#runs and
  Lictor::Report normalize for that.
- The msfconsole-era tests were migrated; anything mentioning msfrpcd in
  code is a regression - it is an optional arsenal, not the path.
