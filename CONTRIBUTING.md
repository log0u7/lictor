# Contributing to lictor

lictor orchestrates augure's judgments: it never decides technique
selection, never invents payloads, and every action is trailed. The operator
is the authorization; the README carries the authorized-use disclaimer.

## Setup

```sh
bin/setup                  # deps + toolchain check
bundle exec rspec          # confirm a green baseline (124 examples)
bundle exec standardrb     # zero offenses required
bundle exec ruby bin/lictor --help
```

augure resolves from `../augure` locally, `./augure` in CI (see the Gemfile).

## Issues

- Open issues through the templates: **Bug report** or **Feature request**
  (search for duplicates first). Reproductions use the lab targets and the
  six-target hardening matrix; never live targets.
- **Security problems never go to public issues.** Use GitHub private
  vulnerability reporting (see `SECURITY.md`).
- Inactive issues may be marked stale after 23 days and closed 7 days later
  without updates.

## Branching

- One branch per topic, cut from `main`:
  `feat/<scope>`, `fix/<scope>`, `chore/<scope>`, `docs/<scope>`, `test/<scope>`.
- `main` stays green at all times.
- Keep branch scope small: one topic, one review, one merge.

## Commits

**Conventional Commits, atomic, English:**

```
feat(verify): carry flag-regex oracle outcome into the trail
fix(trail): close the JSONL file descriptor on resume
test(priors): pin the closed-loop prior update
docs(readme): expand the engagement report example
chore(ci): bump the actions group
```

- Types: `feat`, `fix`, `test`, `docs`, `chore`, `refactor`, `perf`.
- Subject <= 50 chars, imperative mood. Body explains *why*.
- One commit = one change **plus its test**; bug fixes ship a regression test
  that fails on `main` before the fix.
- `CHANGELOG.md` `[Unreleased]` is updated in the same commit for `feat`/`fix`.

## Pull requests

`main` is protected (repository ruleset): direct pushes are rejected.

1. Branch off `main`, implement with TDD, keep the suite green.
2. Open the PR: Conventional Commit title, `Fixes #N` when an issue exists,
   complete the template checklist honestly.
3. CI must be green (rspec, gem builds for lictor and lictor-mcp).
4. Merge with a merge commit, delete the branch.

Review expectations scale with contributors: while the maintainer is the
single author, own PRs are self-merged; with a second contributor, reviews
become required.

## The rules

1. **The OPERATOR is the authorization.** No gates, no tokens, no allowlist
   file. The trail is the record.
2. **Handoff is the default; `plan` executes nothing.**
3. **Every action is trailed**: decision -> rule provenance -> recipe ->
   outcome (JSONL, 0600).
4. **lictor never decides**: it consumes augure; outcomes feed back through
   `Lictor::Priors.from_trail`, never by touching augure's internals.
5. **No exploit code**: the exploits live in the operator's ronin repos;
   lictor orchestrates them. `lictor build` measures (offset under the
   debugger, return address from facts, committed assembly stubs). The
   exploit NAME always comes from the operator's ronin repos.
6. **TDD, no exceptions.** A PR with no test is a rejected PR.
7. **SemVer.** Development is `0.y.z`: minor bumps may break.

## Lint and checks

```sh
bundle exec rspec          # all green required
bundle exec standardrb     # no offenses required
```

## Releasing

1. Update `CHANGELOG.md`: move `[Unreleased]` to a dated section.
2. Bump `lib/lictor/version.rb`.
3. `git commit -m "chore(release): v0.x.y"` through a pull request.
4. Tag `vX.Y.Z` on `main` AFTER the merge lands, on the exact merge commit,
   push tags one by one. The `release` workflow builds and pushes the gems.