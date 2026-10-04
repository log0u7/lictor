# ADR 0003: engagement state is a directory per target, not a database

## Status

Accepted (2026-10-04). Implemented in the engagement phase.

## Context

Today the state model is CWD-global: `target.facts`, `payload.bin`,
`crash-input.bin` are overwritten per acquire/build/fuzz, so two
targets cannot be held at once and the demo only works because it is
strictly sequential. The trail (append-only JSONL) is the event log;
nothing restores state from it.

## Decision

A named target owns a directory: `targets/<name>/` holding its fact
base, payloads, crash inputs and (later) its run manifest. The
`lictor.yml` registry maps names to host:port and binary source. Priors
become per-target with a global blend. Resume reads the trail and the
manifest - no state machine beyond the directory layout. Deliberately
NOT a database, an ORM, or a service: files a human can `cat`.

## Consequences

- Two targets coexist; `--target name` scopes every command; the
  sequential-demo constraint dies.
- The resume path is file-based and boring: interruption leaves
  files, not orphans.
- Scale ceiling: hundreds of targets on one filesystem is fine; a
  distributed engagement graph was never the product (single-operator
  tool, KISS holds until it measurably hurts).