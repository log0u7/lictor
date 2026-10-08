# The demo art

`demo.tape` is the SOURCE; `demo.gif` is the render. From the repo root:

```sh
docker compose -f lab/docker-compose.yml up -d --build
env -u PROMPT_COMMAND -u STARSHIP_SHELL -u STARSHIP_SESSION_KEY \
  mise x vhs@latest -- vhs docs/art/demo.tape
```

(The `env -u` strips the host shell's starship hooks. The tape is
self-sufficient: its first line - typed under `Hide`/`Show`, so never
on screen - strips them too, creates `/tmp/lictor-demo`, writes its
`lictor.yml` and cds there. The render is clean whatever the invocation
and no host path ever leaks into the gif.)

- The pacing: typing 30 ms, dwell 2000 ms, the final hold 5 s.
- The gif is NEVER CI-generated: a bot committing the gif is a push
  conflict waiting to happen.
