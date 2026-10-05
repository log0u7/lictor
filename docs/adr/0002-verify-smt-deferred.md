# ADR 0002: verify is the arithmetic check; SMT stays a seam, not a promise

## Status

Accepted (2026-10-04). Enforced by `Pipeline.analyze` no longer
accepting `solver:` (the dead parameter was removed).

## Context

"Verify" is a sold pillar of the decision payload (`verified` is a
first-class field of `augure/decision@1`), but the pipeline's verify
layer is the arithmetic feasibility check (`payload_fits`); the SMT
machinery (`Verifier.payload_fits_smtlib` + `SmtProcess`, the z3 /
bitwuzla / cvc5 subprocess boundary with `:unknown` semantics) is
tested but never wired into the production flow. Accepting a `solver:`
parameter and ignoring it made the API lie about what the decision
does.

## Decision

The pipeline runs arithmetic verification and says so. The SMT path is
a supported seam for consumers who want it (the how-to-swap-solver doc
stands), but nothing in augure pretends an SMT solver gates decisions.
Technique-specific numerical preconditions would enter as a check
registry when real checks exist to register - not as a stub registry.

## Consequences

- The auditability doc and the README describe verify accurately:
  arithmetic feasibility in the pipeline, SMT available at the seam.
- No fake SMT story to maintain; the `:unknown` semantics and the
  subprocess policy stay tested and ready for the day a check warrants
  solver power.
- The claims discipline holds: the verify pillar is sold for what it
  does, not for what it could do.
