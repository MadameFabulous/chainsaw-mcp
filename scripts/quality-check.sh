#!/usr/bin/env bash
# Unit gates need no forensic samples, live API credentials, or production access.
set -euo pipefail
cd "$(dirname "$0")/.."
UV="${UV:-uv}"
"$UV" sync --locked --group dev
"$UV" run --locked ruff check src tests scripts
"$UV" run --locked mypy
"$UV" run --locked pytest -m 'not integration' --cov --cov-report=term-missing --cov-report=xml
"$UV" run --locked python scripts/check-tool-docs.py
for script in deploy/*.sh scripts/*.sh; do
    bash -n "$script"
done
# The backend and its dependencies are locked in the dev group, not resolved during build.
"$UV" run --locked --no-sync python -m hatchling build
"$UV" run --locked python scripts/check-package.py
