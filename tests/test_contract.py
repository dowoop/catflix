"""Attack the published entitlement contract on a running node.

`test_units.py` proves the Python side refuses things. This proves the CONTRACT
refuses them -- which is the half that matters, because the contract is the
only part of this system that runs on machines belonging to strangers.

Needs a local Freenet node and a published contract. Without them it says so
and skips, rather than passing quietly: a security test that silently does
nothing is worse than no test.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gatekeeper"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import envelope as E
import gatekeeper as G

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASS if condition else FAIL).append(name)
    print(f"  {'ok  ' if condition else 'FAIL'} {name}" + (f"   {detail}" if detail else ""))


def push(contract: str, state: dict) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(state, fh, separators=(",", ":"))
        path = fh.name
    result = subprocess.run(["fdev", "execute", "update", contract, path],
                            capture_output=True, text=True, timeout=300)
    return result.returncode, (result.stderr + result.stdout)


def read_state(contract: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        path = fh.name
    subprocess.run(["fdev", "execute", "get", contract, "-o", path],
                   capture_output=True, text=True, timeout=300)
    body = Path(path).read_text()
    return json.loads(body) if body.strip() else {"entitlements": []}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: test_contract.py <entitlement contract key>")
        return 2
    contract = sys.argv[1]

    if not (G.KEYS / "gatekeeper.ed25519").exists():
        print("SKIP: no gatekeeper key. Run `gatekeeper.py init` first.")
        return 2

    before = read_state(contract)
    print(f"\nattacking {contract}")
    print(f"  contract currently holds {len(before.get('entitlements', []))} entitlement(s)")

    gk = G.signing_key()
    bundle = b'{"v":2,"grants":{}}'
    victim = X25519PrivateKey.generate().public_key().public_bytes_raw()

    # 1. An envelope signed by somebody who is not the gatekeeper.
    impostor = Ed25519PrivateKey.generate()
    forged = E.issue(bundle, victim, 1_788_000_000, 4_102_444_800, impostor, seq=1)
    code, out = push(contract, E.register([forged]))
    check("refuses an envelope signed by another key", code != 0)
    check("  and says why", "not signed by this contract's gatekeeper" in out,
          "" if "not signed" in out else out[:120])

    # 2. A GENUINE envelope with its expiry edited. The signature is real; the
    #    bytes it commits to are not these bytes.
    genuine = E.issue(bundle, victim, 1_788_000_000, 1_790_000_000, gk, seq=1)
    tampered = dataclasses.replace(genuine, expires_at=4_102_444_800)
    code, out = push(contract, E.register([tampered]))
    check("refuses a genuine envelope with an edited expiry", code != 0)

    # 3. A genuine envelope relabelled as being for a different subscriber.
    stolen = dataclasses.replace(genuine, sub=E.b64(X25519PrivateKey.generate()
                                                    .public_key().public_bytes_raw()))
    code, out = push(contract, E.register([stolen]))
    check("refuses an envelope relabelled to another subscriber", code != 0)

    # 4. Unsorted state -- the canonical ordering the contract demands.
    a = E.issue(bundle, X25519PrivateKey.generate().public_key().public_bytes_raw(),
                1_788_000_000, 1_790_000_000, gk, seq=1)
    b = E.issue(bundle, X25519PrivateKey.generate().public_key().public_bytes_raw(),
                1_788_000_000, 1_790_000_000, gk, seq=1)
    pair = sorted([a, b], key=lambda e: e.sub, reverse=True)
    code, out = push(contract, {"v": 1, "entitlements": [e.as_json() for e in pair]})
    check("refuses a state that is not in canonical order", code != 0)

    # 5. Wrong format version.
    code, out = push(contract, {"v": 99, "entitlements": []})
    check("refuses an unrecognised format version", code != 0)

    # 6. THE CONTROL. If every push above failed because pushes always fail,
    #    the five checks above prove nothing at all.
    honest = E.issue(b'{"v":2,"grants":{"a":1}}', victim, 1_788_000_000, 1_790_000_000, gk, seq=5)
    code, out = push(contract, E.register([honest]))
    check("ACCEPTS a genuine envelope (control)", code == 0, "" if code == 0 else out[:160])

    # 7. A REPLAYED older issuance must not displace a newer one. This is the
    #    property that stops somebody's second purchase being erased by a
    #    stale envelope that is still perfectly well signed.
    stale = E.issue(b'{"v":2,"grants":{}}', victim, 1_788_000_000, 4_102_444_800, gk, seq=2)
    code, out = push(contract, E.register([stale]))
    landed = read_state(contract)
    mine = [e for e in landed.get("entitlements", []) if e["sub"] == E.b64(victim)]
    check("a replayed older issuance is accepted but does not win",
          code == 0 and mine and mine[0]["seq"] == 5,
          f"seq is {mine[0]['seq'] if mine else 'missing'}, expected 5")

    after = read_state(contract)
    subs = {e["sub"] for e in after.get("entitlements", [])}
    check("the genuine envelope landed", E.b64(victim) in subs)
    # Checked by SIGNATURE, not by expiry. The perpetual expiry is legitimate
    # -- a portrait bought outright carries it, and the stale-replay case above
    # pushes one deliberately -- so "nothing expires in 2100" stopped being a
    # statement about forgery the moment titles could be bought and kept.
    landed_sigs = {e["sig"] for e in after.get("entitlements", [])}
    check("no forged envelope reached the state", forged.sig not in landed_sigs)
    check("no tampered envelope reached the state", tampered.sig not in landed_sigs)
    check("no relabelled envelope reached the state", stolen.sig not in landed_sigs)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
