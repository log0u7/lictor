#!/bin/sh
# The augure/lictor demo: FOUR targets, four different fact bases,
# four different decisions - the decision layer's showcase.
# Run from anywhere: sh lictor/lab/demo.sh
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WORK=$(mktemp -d)
printf 'trail: demo-trail.jsonl\n' >"$WORK/lictor.yml"

L="$ROOT/bin/lictor"

echo "=== 0. the lab is up (docker compose up -d --build) ==="
docker compose -f lab/docker-compose.yml up -d --build >/dev/null
sleep 1

echo "=== 1. scan (nmap finds the services, recorded in the trail) ==="
(cd "$WORK" && "$L" scan 127.0.0.1) | head -6

# target:port  binary  (the binaries are served over http)
STEP=2
for entry in "127.0.0.1:9999 ret2func" "127.0.0.1:9998 ret2plt" \
	"127.0.0.1:9997 shellcode" "127.0.0.1:9996 fmtstr"; do
	set -- $entry
	TGT=$1
	BIN=$2
	echo
	echo "=== $STEP. target $TGT ($BIN): acquire -> decide -> build -> run ==="
	STEP=$((STEP + 1))

	echo "[acquire] the binary: downloaded, ELF-checked, profiled, recorded"
	(cd "$WORK" && "$L" acquire "$TGT" --from "http://127.0.0.1:8000/$BIN") | head -2

	echo "[decide] augure reads the facts and ranks the verified techniques:"
	(cd "$WORK" && "$L" plan target.facts) | head -6

	echo "[build] the offset is MEASURED (cyclic pattern under the debugger):"
	(cd "$WORK" && "$L" build "$BIN" --facts target.facts -o payload.bin) | head -4

	echo "[run] the closed loop (the executor discovers the exploit in the repos):"
	(cd "$WORK" && "$L" run "$TGT" --facts target.facts \
		--executor ronin --payload payload.bin --max-attempts 2) | head -4
done

echo
echo "=== 6. the auditable engagement report (all four targets) ==="
(cd "$WORK" && "$L" report) | tail -30

echo
echo "demo done - the trail: $WORK/demo-trail.jsonl"
