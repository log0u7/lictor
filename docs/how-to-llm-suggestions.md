# How to let an LLM agent propose facts (not verdicts)

The agent reads the service, its banners, its behavior. That knowledge
is worth something - as FACTS. The `suggest_facts` MCP tool takes the
agent's observations, validates them against the same closed schema as
any facts file, and lets augure re-decide on the merged base. The CLI
persists: `lictor suggest target.facts 'fact("atom").' -o target.facts`
writes the merged base (the MCP tool returns the delta only - the
scoping and the persistence are the operator CLI's job). Under
`--target NAME`, the facts live in `targets/NAME/target.facts`.
`harvest --facts PATH` appends the banner's leaked addresses to the
same base. The agent proposes; augure disposes; the CLI writes.

## The whitelist is structural

There is no `applicable()` predicate to forge. An agent writing
`applicable(ret2plt).` gets rejected by the schema, the same way a
typo would. Suggested facts can only describe the target
(`vuln("sof").`, `plt("system").`, `glibc_minor(31).`, ...), never a
verdict.

## The flow

1. Build the base facts the honest way (scan, acquire, profile).
2. Hand the agent the `suggest_facts` tool with the `.facts` path and
   its hypothesis facts.
3. The tool returns the delta: what was added, applicable before and
   after, selected before and after. A suggestion that changes nothing
   says so.
4. Every suggestion lands in the trail (`type: "suggest"`): who
   proposed what, what changed. The engagement report stays the single
   audit surface.

## What a good suggestion looks like

Observations, not conclusions:

```
glibc_minor(31).            # the banner leaked the glibc version
plt("system").              # an import you spotted in the binary
service("http").            # what the port actually speaks
```

Not:

```
vuln("sof").                # inference - let the engine derive it
```

The engine already derives vulnerability classes from the facts it
trusts; a suggested `vuln(...)` is indistinguishable from a hallucinated
one, which is exactly why observations beat conclusions.
