# lictor-mcp

The MCP surface of the lictor orchestrator: seven tools over stdio,
validated **server-side** - the pack armor, the corpus guard, the
trail (0600). The agent proposes; augure disposes; lictor executes;
the trail records everything.

## The tools

| Tool | What it does | Notes |
|---|---|---|
| `scan_target` | nmap against a target (trailed) | |
| `plan_technique` | profile if ELF, decide (augure), the provenance back | `--json`-shaped (`augure/decision@1`) |
| `execute_technique` | run the decided technique via the operator's ronin repos | discovery by the naming convention; the trail records what actually executed |
| `suggest_facts` | propose observations as facts, get the decision delta | returns the delta only - the CLI's `suggest -o` persists |
| `build_payload` | measured offset + fact-sourced addresses -> the payload file | the chain slots resolve from the facts |
| `scaffold_exploit` | draft the ronin exploit into the operator's repo | review before commit |
| `validate_pack` | run the full pack armor + the corpus guard, dry-run | the write door is `lictor rule install` (the operator's CLI, interactive) |

## Run

```sh
gem install lictor-mcp        # or bundle from the checkout
lictor-mcp                    # stdio MCP server
```

## Honest gaps

- `execute_technique` has no `--flag-regex` equivalent yet: the success
  semantics stay the runner's exit code (the CLI's oracle supersedes
  it; the MCP surface is next).
- The MCP cannot drive acquire/harvest/verify/report/target - those
  are the operator's CLI steps.
