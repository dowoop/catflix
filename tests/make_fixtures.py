"""Build the state corpus `fdev verify-merge` replays against the contract.

The states are DELIBERATELY the awkward ones. A corpus of unrelated
entitlements would pass a merge check that a lattice bug still fails, because
the interesting cases are the ones where two states disagree about the SAME
subscriber -- which is exactly what a renewal is.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gatekeeper"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import envelope as E

OUT = Path(__file__).parent / "fixtures"

# Fixed seeds: a corpus that changes every run cannot be compared against a
# previous finding, and "it passed last time" stops meaning anything.
GATEKEEPER_SEED = bytes(range(32))
SUBSCRIBER_SEEDS = [bytes([i]) * 32 for i in (1, 2, 3)]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    gk = Ed25519PrivateKey.from_private_bytes(GATEKEEPER_SEED)
    (OUT / "params.bin").write_bytes(gk.public_key().public_bytes_raw())

    subs = [X25519PrivateKey.from_private_bytes(s) for s in SUBSCRIBER_SEEDS]
    pubs = [s.public_key().public_bytes_raw() for s in subs]

    def ent(i: int, seq: int, expires: int = 1_790_000_000):
        return E.issue(b'{"v":2,"grants":{}}', pubs[i], 1_788_000_000, expires, gk, seq=seq)

    a, b, c = ent(0, 1), ent(1, 1), ent(2, 1)
    # The second purchase: same subscriber as `a`, higher seq. The join must
    # take it -- its bundle is a superset of the one in `a`.
    a_renewed = ent(0, 2, 1_795_000_000)
    # A STALE envelope for the same subscriber, at a seq already superseded.
    # The join must NOT take it in either arrival order; that is the property
    # that stops a replayed old envelope from erasing a later purchase.
    a_stale = ent(0, 1, 1_789_000_000)

    states = {
        "empty": {"v": 1, "entitlements": []},
        "a": E.register([a]),
        "b": E.register([b]),
        "ab": E.register([a, b]),
        "abc": E.register([a, b, c]),
        "a_renewed": E.register([a_renewed]),
        "a_renewed_b": E.register([a_renewed, b]),
        "a_stale": E.register([a_stale]),
    }
    for name, state in states.items():
        (OUT / f"{name}.json").write_text(json.dumps(state, separators=(",", ":")))

    print(f"wrote {len(states)} states + params to {OUT}")
    for name in states:
        print(f"  {name}.json  {(OUT / f'{name}.json').stat().st_size} bytes")


if __name__ == "__main__":
    main()
