#!/bin/sh
# The lictor speed benchmark: the CLI boot, the plan path, the suite.
#   sh tools/bench.sh
set -e
cd "$(dirname "$0")/.."
B=$(mktemp)
echo "boot (--help), 5 cold runs:"
for i in 1 2 3 4 5; do /usr/bin/time -f "  %e s" bin/lictor --help >/dev/null 2>>"$B"; done
cat "$B"

D=$(mktemp -d)
printf 'trail: t.jsonl\npacks: %s/augure/packs\n' "$(pwd)/.." >"$D/lictor.yml"
echo "plan end-to-end (cold CLI, split.facts, stubbed profiler):"
B2=$(mktemp)
for i in 1 2 3; do
	/usr/bin/time -f "  %e s" bin/lictor plan ../augure/examples/split.facts -t "$D/t.jsonl" --profile-cmd "true" >/dev/null 2>>"$B2" || true
done
cat "$B2"
echo "(the suite: time bundle exec rspec - run separately)"
