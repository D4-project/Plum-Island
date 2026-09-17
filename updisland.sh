#!/usr/bin/env bash
set -euo pipefail

git pull --ff-only origin main
git submodule sync --recursive
git submodule update --init --recursive
