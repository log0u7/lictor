# The demo art

`demo.tape` is the SOURCE; `demo.gif` is the render. Regenerate:

```sh
env -u PROMPT_COMMAND -u STARSHIP_SHELL -u STARSHIP_SESSION_KEY \
  mise x vhs@latest -- vhs docs/art/demo.tape
```

(The `env -u` strips the host shell's starship hooks; the tape's first
line also unsets them, so the render is clean whatever the invocation.)

- vhs reads no shell rc: the setup is typed as the tape's first line.
- The pacing: typing 30 ms, dwell 2000 ms, the final hold 5 s.
- The gif is NEVER CI-generated: a bot committing the gif is a push
  conflict waiting to happen.
