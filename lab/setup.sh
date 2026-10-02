#!/bin/sh
# Lab setup: the ronin toolchain + the local exploit repo.
# Run from lictor/lab/: sh setup.sh
set -e

gem list -i ronin-exploits >/dev/null 2>&1 || gem install ronin-exploits --no-document

# The local repo must be a git repo (ronin-repos installs git URLs).
cd "$(dirname "$0")/ronin-repo"
git init -q 2>/dev/null || true
git add -A
git -c user.name=lab -c user.email=lab@local commit -qm "lab exploits" 2>/dev/null || true

REPO_URL="file://$(pwd)"
cd -
ronin-repos list 2>/dev/null | rtk grep -q augure-lab 2>/dev/null ||
	ronin-repos install "$REPO_URL" --name augure-lab ||
	ronin-repos install "$REPO_URL"

echo "lab setup done:"
echo "  ronin-exploits list   # should show lab_ret2func_001"
