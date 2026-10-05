#!/bin/sh
# The purple demo: the HARDENING MATRIX - the same sources compiled
# under full hardening (canary, PIE, full RELRO, FORTIFY), served on
# the 889x ports. The loop: acquire the hardened variant, plan, and
# WATCH THE DECISION DIE - then augure coverage says what survives
# and what the attacker's next moves are.
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WORK=$(mktemp -d)
printf 'trail: purple-trail.jsonl\npacks: %s/../augure/packs\n' "$ROOT" >"$WORK/lictor.yml"
L="$ROOT/bin/lictor"

echo "=== the hardened mirrors (the decision dies against them) ==="
echo "the 889x services: ret2func_h 8899, ret2plt_h 8898, shellcode_h 8897 -"
echo "the same sources compiled canary+PIE+RELRO+FORTIFY. Acquire one and"
echo "the plan's applicable set shrinks; the demo runs the corpus flip instead:"
echo "  lictor acquire 127.0.0.1:8899 --from http://127.0.0.1:8000/ret2func_h"
echo "  lictor plan target.facts    # the decision, one technique down"

echo
echo "=== augure coverage: the hardening flips against the built-in corpus ==="
(cd "$ROOT/../augure" && bundle exec ruby exe/augure coverage --flip canary:true) | head -8
echo
(cd "$ROOT/../augure" && bundle exec ruby exe/augure coverage --flip nx:true canary:true pie:true relro:full) | head -10

echo
echo "=== the defender view of an ATTACK trail (the demo's trail, read backwards) ==="
if [ -f "$ROOT/lictor-trail.jsonl" ]; then
	(cd "$WORK" && "$L" report --defender -t "$ROOT/lictor-trail.jsonl") | head -20
else
	echo "(no attack trail yet - run lab/demo.sh first, then the defender view reads its trail)"
fi

echo
echo "purple demo done - the trail: $WORK/purple-trail.jsonl"
