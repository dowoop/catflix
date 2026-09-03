#!/usr/bin/env bash
# Every gate Catflix has, in one answer.
#
# Ordered cheapest-first so a broken build fails in seconds rather than after
# a round trip to a node. The last stage needs a running node and a published
# contract; it SKIPS loudly rather than passing quietly when they are absent,
# because a security gate that silently does nothing is worse than none.
set -uo pipefail
cd "$(dirname "$0")"

FAILED=0
stage() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
verdict() { if [ "$1" -eq 0 ]; then echo "  PASS"; else echo "  FAIL"; FAILED=1; fi; }

stage "unit refusals (sealing, references, price, ledger)"
python3 tests/test_units.py | tail -3
verdict "${PIPESTATUS[0]}"

stage "the page charges what the seller demands"
if [ -f site/config.json ]; then
    node tests/test_pricing.js | tail -3
    verdict "${PIPESTATUS[0]}"
else
    echo "  SKIP: no site/config.json -- run ./catflix up"
fi

stage "the merge law the network enforces"
python3 tests/make_fixtures.py >/dev/null
F=tests/fixtures
for W in contract/target/wasm32-unknown-unknown/release/catflix_entitlements.wasm; do
    if [ ! -f "$W" ]; then echo "  SKIP: $W not built -- run ./build.sh"; continue; fi
    fdev verify-merge --wasm "$W" --params "$F/params.bin" \
        --state $F/empty.json --state $F/a.json --state $F/b.json --state $F/ab.json \
        --state $F/abc.json --state $F/a_renewed.json --state $F/a_renewed_b.json \
        --state $F/a_stale.json \
        --transition $F/a.json $F/ab.json --transition $F/a.json $F/a_renewed.json \
        --transition $F/ab.json $F/abc.json 2>&1 | grep -E "case\(s\) run|no enforceable|enforceable violation"
    # `verify-merge` exits 0 on diagnostic-only findings, so the exit code
    # alone does not say the laws held. The line does.
done

stage "the contract's own refusals, against a running node"
CONTRACT=$(python3 -c "
import json,pathlib
p=pathlib.Path('site/config.json')
print(json.loads(p.read_text())['contract'] if p.exists() else '')" 2>/dev/null)
if [ -z "$CONTRACT" ]; then
    echo "  SKIP: no site/config.json -- run ./build.sh"
elif ! curl -s -m 5 -o /dev/null "http://127.0.0.1:7509/" 2>/dev/null && \
     ! ss -ltn 2>/dev/null | grep -q ":7509"; then
    echo "  SKIP: no Freenet node on 127.0.0.1:7509 -- start one with \`freenet local\`"
else
    python3 tests/test_contract.py "$CONTRACT" | tail -4
    verdict "${PIPESTATUS[0]}"
fi

stage "verdict"
if [ "$FAILED" -eq 0 ]; then echo "  everything that can be checked here holds"; else echo "  SOMETHING FAILED"; fi
exit "$FAILED"
