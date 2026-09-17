#!/usr/bin/env bash
set -euo pipefail

git pull --ff-only origin main
git submodule sync --recursive
git submodule update --init --recursive
# Tag rules are updated independently from Plum-Island releases. Fetch their
# remote tip instead of leaving this submodule at the commit pinned by the
# parent repository.
git submodule update --init --remote webapp/tags
