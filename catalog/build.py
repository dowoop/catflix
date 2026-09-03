"""Build the catalogue: posters in the clear, full portraits encrypted.

## The split, and why it is where it is

The poster is free. The portrait is not. That is the same split a streaming
service makes -- browse the artwork without an account, watch nothing -- and
it is the only split that survives being published on Freenet, where every
byte of contract state and every file in the web container is readable by
anyone who asks for it.

So "free" here does not mean "served differently". It means the poster is
plaintext and the portrait is AES-GCM ciphertext, sitting in the same
directory, replicated to the same peers. An unpaid visitor downloads both and
can open one.

## One key per title, because a title is now what you buy

There was a single key per epoch while the only thing for sale was
all-of-it-for-a-month. The moment a single portrait became orderable, one
shared key meant buying one portrait handed over all nine — the envelope would
have carried the key that opens everything.

So each title gets its own AES-256 key. "All access" is then simply a bundle
containing all nine, and there is no separate mechanism for it.

## Nonce uniqueness is checked, not assumed

Every image gets a fresh 12-byte nonce under one epoch key. Two images sharing
a nonce under one key would let anyone XOR the ciphertexts together and
recover the XOR of the plaintexts -- catastrophic, and invisible in every
rendering test because both images still decrypt correctly for a subscriber.
`os.urandom` will not collide in twelve bytes, and this asserts it anyway: the
cost is a set lookup and the failure it catches is silent.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gatekeeper"))
import envelope as E  # noqa: E402
from envelope import b64  # noqa: E402

from cats import draw_cat, poster_from  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
KEYS = ROOT / "keys"

# Domain-separated AAD, so a ciphertext cannot be moved between titles or
# epochs and still open. The id and epoch are authenticated but not secret.
AAD_DOMAIN = b"catflix-title-v1"

EPOCH = 1

# The short code that travels in a payment reference. A title id like
# "nine-and-counting" would fit inside the component's 128-byte bound, but only
# just, and the bound is not the thing to spend on prose: `t3` leaves room.
def sku_for(index: int) -> str:
    return f"t{index}"


TITLES = [
    ("tabby-nights", "Tabby Nights", 2026, "1h 42m",
     "A retired mouser takes one last job in a city that forgot how to purr."),
    ("the-long-nap", "The Long Nap", 2025, "2h 08m",
     "Fourteen hours of sunlight moving across a rug. Critics called it brave."),
    ("box-fits", "Box Fits", 2026, "1h 12m",
     "It should not have fitted. It fitted. A documentary about certainty."),
    ("nine-and-counting", "Nine and Counting", 2024, "1h 55m",
     "An actuary attempts to price a life that keeps not ending."),
    ("the-red-dot", "The Red Dot", 2026, "58m",
     "A thriller. The antagonist is never caught and does not exist."),
    ("kitchen-counter", "Kitchen Counter", 2025, "1h 33m",
     "Forbidden territory, surveyed nightly. Nobody is ever prosecuted."),
    ("three-a-m", "Three A.M.", 2026, "44m",
     "Experimental. Sustained percussion on a bedroom door, no resolution."),
    ("the-vet-visit", "The Vet Visit", 2023, "1h 21m",
     "A horror film shot entirely inside a plastic carrier. Restored 4K."),
    ("windowsill", "Windowsill", 2026, "3h 02m",
     "Slow cinema at its most committed. Nothing happens. Twice."),
]


def main() -> None:
    KEYS.mkdir(exist_ok=True)
    key_path = KEYS / "content-titles.json"
    # Keys are REUSED when they exist. Minting fresh ones would re-encrypt the
    # catalogue under keys nobody has been sold, silently locking out every
    # existing customer while every test still passed.
    keys = json.loads(key_path.read_text()) if key_path.exists() else {}
    minted = 0
    for tid, *_ in TITLES:
        if tid not in keys:
            keys[tid] = b64(AESGCM.generate_key(bit_length=256))
            minted += 1
    key_path.write_text(json.dumps(keys, indent=1))
    key_path.chmod(0o600)
    print(f"{len(keys)} title keys in {key_path.name}"
          + (f" ({minted} newly minted)" if minted else " (all reused)"))

    (SITE / "posters").mkdir(parents=True, exist_ok=True)
    (SITE / "enc").mkdir(parents=True, exist_ok=True)

    used_nonces: set[bytes] = set()
    entries = []

    for index, (tid, title, year, runtime, synopsis) in enumerate(TITLES):
        aead = AESGCM(E.unb64(keys[tid]))
        full = draw_cat(index * 7 + 3)
        poster = poster_from(full)

        buf = io.BytesIO()
        full.save(buf, format="WEBP", quality=88)
        plaintext = buf.getvalue()

        poster_name = f"posters/{tid}.webp"
        poster.save(SITE / poster_name, format="WEBP", quality=80)

        nonce = os.urandom(12)
        if nonce in used_nonces:  # pragma: no cover -- 2^-96, checked anyway
            raise SystemExit("nonce collision under one epoch key; refusing to write")
        used_nonces.add(nonce)

        aad = AAD_DOMAIN + tid.encode() + EPOCH.to_bytes(4, "big")
        ciphertext = aead.encrypt(nonce, plaintext, aad)
        enc_name = f"enc/{tid}.bin"
        (SITE / enc_name).write_bytes(ciphertext)

        entries.append({
            "id": tid, "title": title, "year": year, "runtime": runtime,
            "synopsis": synopsis, "poster": poster_name, "enc": enc_name,
            "nonce": b64(nonce), "epoch": EPOCH, "sku": sku_for(index),
            "bytes": len(ciphertext),
            "sha256": hashlib.sha256(ciphertext).hexdigest()[:16],
        })
        print(f"  {title:22} poster {len(poster.tobytes())//1024:>4} KiB raw   sealed {len(ciphertext)//1024:>4} KiB")

    manifest = {
        "v": 1,
        "epoch": EPOCH,
        "titles": entries,
    }
    (SITE / "catalog.json").write_text(json.dumps(manifest, indent=1))
    print(f"\nwrote {len(entries)} titles, {len(used_nonces)} distinct nonces, one key each")
    print(f"manifest -> {SITE / 'catalog.json'}")


if __name__ == "__main__":
    main()
