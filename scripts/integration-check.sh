#!/usr/bin/env bash
# Real, reproducible integration tier: never silently succeed through skipped tests.
set -euo pipefail
cd "$(dirname "$0")/.."
UV="${UV:-uv}"
SAMPLES_REV=4ceed2f4706daf601c212a8f91c113dd85349a2c
SAMPLES=evidence/EVTX-ATTACK-SAMPLES
"$UV" sync --locked --group dev
# bootstrap verifies both the release archive and the Linux x86_64 executable digests.
"$UV" run --locked chainsaw-mcp-bootstrap --force
if [[ ! -e "$SAMPLES" ]]; then
    git init "$SAMPLES"
    git -C "$SAMPLES" remote add origin https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
    git -C "$SAMPLES" fetch --depth=1 origin "$SAMPLES_REV"
    git -C "$SAMPLES" checkout --detach FETCH_HEAD
fi
[[ "$(git -C "$SAMPLES" rev-parse HEAD)" == "$SAMPLES_REV" ]]
[[ -z "$(git -C "$SAMPLES" status --porcelain)" ]]
[[ -x vendor/chainsaw/chainsaw ]]
[[ -d vendor/chainsaw/sigma/rules ]]
[[ -f "$SAMPLES"/'Credential Access/babyshark_mimikatz_powershell.evtx' ]]
[[ -f "$SAMPLES"/'Credential Access/tutto_malseclogon.evtx' ]]
# Prevent host configuration from redirecting the binary or enabling external AI calls.
export CHAINSAW_BIN="$PWD/vendor/chainsaw/chainsaw"
export CHAINSAW_JEV_ENABLED=false
"$UV" run --locked pytest -m integration --junitxml=integration-results.xml
"$UV" run --locked python -c '
import xml.etree.ElementTree as ET
root = ET.parse("integration-results.xml").getroot()
suites = list(root.iter("testsuite"))
assert sum(int(s.get("tests", 0)) for s in suites) > 0, "No integration tests ran"
assert not any(int(s.get("skipped", 0)) for s in suites), "Integration tests skipped"
'
