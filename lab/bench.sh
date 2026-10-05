#!/bin/sh
# The bench: replay the lab engagement and export the TELEMETRY - the
# shape the LLM benchmarks want (NYU CTF Bench, InterCode): the tasks,
# the actions, the feedback, one line per event. `lictor run` already
# IS the interactive environment (code = actions, feedback = the trail);
# this script makes it an export.
#
# Usage: sh lab/bench.sh [OUTDIR]   (default: bench/<date>)
set -e
cd "$(dirname "$0")/.."
OUT=${1:-bench/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"

echo "=== the bench: the lab replay, the telemetry exported ==="
sh lab/demo.sh | tee "$OUT/demo.log"

cp -r demo-trail.jsonl "$OUT/trail.jsonl" 2>/dev/null || true
if [ -f "$OUT/trail.jsonl" ]; then
	events=$(wc -l < "$OUT/trail.jsonl")
	outcomes=$(grep -c '"type":"outcome"' "$OUT/trail.jsonl" || true)
	success=$(grep -c '"success":true' "$OUT/trail.jsonl" || true)
	{
		echo "{"
		echo "  \"schema\": \"lictor/bench@1\","
		echo "  \"events\": $events,"
		echo "  \"outcomes\": $outcomes,"
		echo "  \"successes\": $success,"
		echo "  \"note\": \"predictions with provenance, not field results\""
		echo "}"
	} > "$OUT/summary.json"
	cat "$OUT/summary.json"
fi

echo
echo "bench artifacts: $OUT/ (demo.log, trail.jsonl, summary.json)"
