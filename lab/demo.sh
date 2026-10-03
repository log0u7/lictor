#!/bin/sh
# The augure/lictor demo: FOUR targets, four different fact bases,
# four different decisions - the decision layer's showcase.
# Run from anywhere: sh lictor/lab/demo.sh
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WORK=$(mktemp -d)
# The scope: the four lab targets.
printf '127.0.0.1:9996\n127.0.0.1:9997\n127.0.0.1:9998\n127.0.0.1:9999\n' >"$WORK/targets.yml"
printf 'allowlist: targets.yml\ntrail: demo-trail.jsonl\n' >"$WORK/lictor.yml"

L="$ROOT/bin/lictor"
P="$ROOT/../augure/profiler/exe/augure-profile"

echo "=== 0. the lab is up (docker compose up -d --build) ==="
docker compose -f lab/docker-compose.yml up -d --build >/dev/null
sleep 1

echo "=== 1. scan (nmap finds the services, recorded in the trail) ==="
(cd "$WORK" && "$L" scan 127.0.0.1 -a targets.yml) | head -6

echo
echo "=== 2..5. per target: acquire -> decide -> authorize -> run ==="
# target:port  binary  (the binaries are served over http)
for entry in "127.0.0.1:9999 ret2func" "127.0.0.1:9998 ret2plt" \
	"127.0.0.1:9997 shellcode" "127.0.0.1:9996 fmtstr"; do
	set -- $entry
	TGT=$1
	BIN=$2
	echo
	echo "--- target $TGT ($BIN) ---"

	echo "[acquire] the binary: downloaded, ELF-checked, profiled, recorded"
	(cd "$WORK" && "$L" acquire "$TGT" --from "http://127.0.0.1:8000/$BIN" -a targets.yml) | head -2

	echo "[decide] augure reads the facts and ranks the verified techniques:"
	(cd "$WORK" && "$L" plan target.facts -a targets.yml) | head -6

	echo "[authorize] the operator types the target; the token lasts 15 min:"
	TOKEN=$(echo "$TGT" | (cd "$WORK" && "$L" authorize "$TGT" -a targets.yml) |
		grep "token:" | awk '{print $2}')
	echo "  token: $(echo "$TOKEN" | cut -c1-8)..."

	echo "[run] the closed loop (the executor discovers the exploit in the repos):"
	echo "$TGT" | (cd "$WORK" && "$L" run "$TGT" --facts target.facts \
		-a targets.yml --executor ronin --consent-token "$TOKEN" --max-attempts 2) | head -4
done

echo
echo "=== 6. the auditable engagement report (all four targets) ==="
(cd "$WORK" && "$L" report) | tail -30

echo
echo "demo done - the trail: $WORK/demo-trail.jsonl"
