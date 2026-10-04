# ADR 0001: the Tube is the transport seam - TCP first, the rest later

## Status

Accepted (2026-10-04). Implemented in the decide->build->run phase.

## Context

Three independent TCP implementations exist today: Harvest's banner
read, verify's crash probe, and the RONIN_MIXINS delivery column. Each
hardcodes connect/read/write with its own timeout semantics. Adding
UDP, TLS or HTTP today means three more copies. pwntools' tube concept
is the proven shape for this layer.

## Decision

One `Lictor::Tube` (connect / read_until / sendline / deadline), the
single implementation behind harvest, verify and the scaffold. New
transports (UDP, TLS, HTTP-aware delivery) become Tube subclasses or
factory entries behind the same seam - the transport stops being a bet
and becomes an extension point.

## Consequences

- The three duplicated socket paths die; one timeout/deadline
  semantics to audit instead of three.
- The scaffolded exploits gain the same read_until discipline the lab
  exploits hand-rolled.
- Local-process delivery (the mirror run fully offline) plugs in as
  another Tube flavor when needed - no interface invented beyond what
  TCP needs today.