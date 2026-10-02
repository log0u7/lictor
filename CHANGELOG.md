# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `lictor scan`: nmap as a gated, trailed action against an allowlisted
  host (subprocess; --nmap override for testing). Scans appear in
  `runs` and in the engagement report.

### Removed

- `--i-am-authorized` and `--target` flags: security theater. A flag
  can be typed by reflex, by a script, or by anyone with shell access -
  it proves nothing and taxes the legitimate user. Authorization is the
  allowlist artifact (explicit host[:port] entries, colon-delimited
  prefix match so .1 cannot pass for .10) plus the trail. A future
  execute command will confirm interactively (show the recipe, type the
  target), never through a flag.

## [0.1.0] - 2026-10-02

### Added

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
