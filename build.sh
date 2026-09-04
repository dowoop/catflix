#!/usr/bin/env bash
# Build everything Catflix publishes, in the order the pieces depend on.
#
# The contract must exist before its address is known, and the address must be
# known before the site can be told where to watch -- so `config.json` is
# written from the address this script computes, never typed. A site published
# with a hand-copied contract key that has since changed looks exactly like a
# site nobody has ever paid.
set -euo pipefail
cd "$(dirname "$0")"

WASM=contract/target/wasm32-unknown-unknown/release/catflix_entitlements.wasm
PARAMS=keys/params.bin

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "contract"
( cd contract && cargo build --release --target wasm32-unknown-unknown 2>&1 | tail -1 )
# The four exports are the whole contract. They vanish silently if the
# `freenet-main-contract` feature is ever dropped from Cargo.toml -- the build
# still succeeds and still writes a .wasm, so this is checked and not assumed.
# NOT `grep`. This machine's grep is ugrep, which applies binary-file
# heuristics and reported all four symbols missing from a .wasm that provably
# contains them. A gate that answers differently depending on how the file
# looks to a heuristic is worse than no gate: it fails loudly on a good build
# and would fail quietly on a bad one.
check_exports() {
    python3 - "$1" <<'PYEOF'
import re, sys
blob = open(sys.argv[1], "rb").read()
want = {"validate_state", "update_state", "summarize_state", "get_state_delta"}
have = {m.decode() for m in re.findall(rb"(validate_state|update_state|summarize_state|get_state_delta)", blob)}
missing = want - have
if missing:
    raise SystemExit(f"FAIL: {sys.argv[1]} exports none of {sorted(missing)}")
print(f"  {len(have)}/4 exports present, {len(blob)} bytes")
PYEOF
}
check_exports "$WASM"

say "request queue contract"
QWASM=contract-requests/target/wasm32-unknown-unknown/release/catflix_requests.wasm
( cd contract-requests && cargo build --release --target wasm32-unknown-unknown 2>&1 | tail -1 )
check_exports "$QWASM"
printf '{"v":1,"refs":[]}' > /tmp/catflix-q0.json
printf '{"v":1,"refs":["CF1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.t0.aaaa"]}' > /tmp/catflix-q1.json
# The code hash is not printed by `get-contract-id`, and the browser needs it:
# an UPDATE addressed by instance id alone is refused, because the node probes
# for the code blob by hash. This run is a real merge gate AND the only place
# the node states that hash, so it is read from here rather than pasted.
QUEUE_LOG=$(fdev verify-merge --wasm "$QWASM" \
    --state /tmp/catflix-q0.json --state /tmp/catflix-q1.json 2>&1)
echo "$QUEUE_LOG" | grep -E "case\(s\) run|no enforceable"
# The node colours its logs, so `code_hash` and the value are separated by
# ANSI escapes that contain letters and digits -- a character class meant to
# skip punctuation walks straight into them. Strip the escapes first.
QUEUE_CODE=$(echo "$QUEUE_LOG" | sed 's/\x1b\[[0-9;]*m//g' \
             | grep -oE "code_hash: [1-9A-HJ-NP-Za-km-z]{43,44}" \
             | grep -oE "[1-9A-HJ-NP-Za-km-z]{43,44}" | head -1)
QUEUE_ID=$(fdev execute get-contract-id --code "$QWASM" 2>&1 \
           | grep -oE "[1-9A-HJ-NP-Za-km-z]{43,44}" | head -1)
[ -n "$QUEUE_CODE" ] && [ -n "$QUEUE_ID" ] || { echo "could not derive the queue contract identity"; exit 1; }
echo "  queue $QUEUE_ID  code $QUEUE_CODE"

say "merge law"
F=tests/fixtures
python3 tests/make_fixtures.py >/dev/null
fdev verify-merge --wasm "$WASM" --params "$F/params.bin" \
    --state $F/empty.json --state $F/a.json --state $F/b.json --state $F/ab.json \
    --state $F/abc.json --state $F/a_renewed.json --state $F/a_renewed_b.json --state $F/a_stale.json \
    --transition $F/a.json $F/ab.json --transition $F/a.json $F/a_renewed.json \
    --transition $F/ab.json $F/abc.json 2>&1 | grep -E "case\(s\) run|no enforceable|violation"

say "contract address"
[ -f "$PARAMS" ] || { echo "no $PARAMS -- run: python3 gatekeeper/gatekeeper.py init"; exit 1; }
CONTRACT=$(fdev execute get-contract-id --code "$WASM" --parameters "$PARAMS" 2>&1 \
           | grep -oE "[1-9A-HJ-NP-Za-km-z]{43,44}" | head -1)
[ -n "$CONTRACT" ] || { echo "could not compute the contract address"; exit 1; }
echo "  $CONTRACT"

say "catalogue"
python3 catalog/build.py | tail -2

say "site"
python3 - "$CONTRACT" "$QUEUE_ID" "$QUEUE_CODE" <<'PY'
import base64, json, sys, pathlib
sys.path.insert(0, "gatekeeper")
import gatekeeper as G

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(text: str) -> bytes:
    """Base58 -> raw bytes. The SDK's ContractKey wants 32 raw bytes, and the
    node speaks base58, so somebody has to convert. Doing it here means the
    browser never carries a base58 decoder for two constants."""
    n = 0
    for ch in text:
        n = n * 58 + ALPHABET.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

contract, queue_id, queue_code = sys.argv[1], sys.argv[2], sys.argv[3]
instance, code = b58decode(queue_id), b58decode(queue_code)
assert len(instance) == 32 and len(code) == 32, "a contract id and code hash are 32 bytes each"

pathlib.Path("site/config.json").write_text(json.dumps({
    "contract": contract,
    "requests": queue_id,
    "requestsInstance": b64u(instance),
    "requestsCode": b64u(code),
    "component": G.COMPONENT,
    "indexer": G.INDEXER,
    "pricePerDay": G.PRICE_MICROXTR_PER_DAY,
    "pricePerTitle": G.PRICE_MICROXTR_PER_TITLE,
}, indent=1))
print(f"  config.json -> entitlements {contract[:12]}..., queue {queue_id[:12]}...")
print(f"               {G.PRICE_MICROXTR_PER_TITLE:,} uXTR a portrait, {G.PRICE_MICROXTR_PER_DAY * 30:,} uXTR all-access/30d")
PY
( cd ui && npx --no-install esbuild app.js --bundle --format=iife --outfile=../site/app.js --minify --log-level=warning )
cp ui/index.html ui/style.css site/
echo "  site/ is $(du -sh site | cut -f1) across $(find site -type f | wc -l) files"

say "done"
echo "publish the UI:   fdev website publish ./site --key catflix"
echo "publish the data: fdev execute put --code $WASM --parameters $PARAMS contract --state run/initial-state.json"
echo "run the seller:   python3 gatekeeper/gatekeeper.py watch --contract $CONTRACT"
