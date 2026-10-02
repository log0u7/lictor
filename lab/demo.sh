#!/bin/sh
# The augure/lictor demo: the whole pipeline against the docker lab.
# Run from anywhere: sh lictor/lab/demo.sh
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WORK=$(mktemp -d)
printf '127.0.0.1:9999\n' >"$WORK/targets.yml"
printf 'allowlist: targets.yml\ntrail: demo-trail.jsonl\n' >"$WORK/lictor.yml"

L="$ROOT/bin/lictor"
P="$ROOT/../augure/profiler/exe/augure-profile"

echo "=== 0. the lab is up (docker compose up -d --build) ==="
docker compose -f lab/docker-compose.yml up -d --build >/dev/null
sleep 1

echo "=== 1. scan (nmap, gated, trailed) ==="
(cd "$WORK" && "$L" scan 127.0.0.1 -a targets.yml) | head -4

echo "=== 2. acquire + profile the binary ==="
curl -s http://127.0.0.1:8000/vuln_service -o "$WORK/vuln_service"
chmod +x "$WORK/vuln_service"
(cd "$WORK" && "$P" vuln_service -o target.facts) | tail -1

echo "=== 3. decide (augure: propose, verify, explain) ==="
(cd "$WORK" && "$L" plan target.facts -a targets.yml) | head -7

echo "=== 4. authorize (the human types the target) ==="
TOKEN=$(echo "127.0.0.1:9999" | (cd "$WORK" && "$L" authorize 127.0.0.1:9999 -a targets.yml) | grep "token:" | awk '{print $2}')
echo "token: $TOKEN"

echo "=== 5. run (the closed loop with the ronin executor) ==="
echo "127.0.0.1:9999" | (cd "$WORK" && "$L" run 127.0.0.1:9999 --facts target.facts \
	-a targets.yml --executor ronin --consent-token "$TOKEN" --max-attempts 2)

echo "=== 6. the auditable report ==="
(cd "$WORK" && "$L" report) | tail -22

echo
echo "demo done - the trail: $WORK/demo-trail.jsonl"
