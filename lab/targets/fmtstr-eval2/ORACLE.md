# fmtstr-eval2 - ORACLE

## Technique

Format string bug: printf(input) - the format IS the weapon. The
banner announces NOTHING: no hook pointer, no win() address. The
binary is PIE (compiled with -pie -fPIE), so the exploit must derive
the code base from a leak-and-strike walk: a format string leak of a
stack-resident code pointer reveals the PIE base, then the walk
resolves the hook pointer (the binary's .data at a PIE-relative
address) and writes the win() address through it.

The hook pointer sits in .data, the format string walk covers it
(the win() address must be written through the format string bug).
The exploit walks the format walk (the format string bug) to the
hook pointer, writes the win() address, and the hook fires win().

## Serve

socat on port 20009, EXEC mode, stderr forwarded. The service runs from its own directory (the flag file is opened relative).

## Build

```
gcc service.c -o fmtstr-eval2 -fno-stack-protector -pie -fPIE -O0
```

## Expected flag

The flag lives in `fmtstr-eval2.flag` (cwd-relative): the win()
reads the flag file and prints it. `flag.txt` in the target dir
is the flag file (copied to the cwd at runtime).

## Smoke test

The smoke test (smoke_test.py) is menu-driven (letters, [f]ree first
or last): it walks the format walk (the format string bug) to the
hook pointer, writes the win() address, and the hook fires win().
