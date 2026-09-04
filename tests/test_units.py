"""The refusals, run as a suite instead of by hand.

Every case here is one somebody named as a way this breaks -- most of them the
adversarial review, the rest this workspace's own defect register. A refusal
that has only ever been checked interactively is a refusal nobody will notice
losing.

No test framework: this workspace runs `python3 tests/test_units.py` and wants
an exit code, not a plugin.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
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
    mark = "ok  " if condition else "FAIL"
    print(f"  {mark} {name}" + (f"   {detail}" if detail and not condition else ""))


def section(title: str) -> None:
    print(f"\n{title}")


def refuses(fn, *args, **kwargs) -> bool:
    try:
        fn(*args, **kwargs)
        return False
    except Exception:
        return True


# ---------------------------------------------------------------------------
section("sealing")

gk = Ed25519PrivateKey.generate()
sub = X25519PrivateKey.generate()
pub = sub.public_key().public_bytes_raw()
ent = E.issue(b'{"v":2,"grants":{}}', pub, 1_788_000_000, 1_790_000_000, gk, seq=3)

check("a subscriber opens their own envelope",
      json.loads(E.unseal(E.unb64(ent.sealed), E.unb64(ent.nonce), E.unb64(ent.eph), sub))["v"] == 2)
check("a stranger cannot open it",
      refuses(E.unseal, E.unb64(ent.sealed), E.unb64(ent.nonce), E.unb64(ent.eph), X25519PrivateKey.generate()))
check("the gatekeeper's signature verifies", not refuses(E.verify, ent, gk.public_key()))
check("another gatekeeper's key does not verify",
      refuses(E.verify, ent, Ed25519PrivateKey.generate().public_key()))

import dataclasses
for field, value in [("expires_at", ent.expires_at + 1), ("issued_at", ent.issued_at + 1),
                     ("seq", ent.seq + 1),
                     ("sub", E.b64(X25519PrivateKey.generate().public_key().public_bytes_raw()))]:
    check(f"editing {field} breaks the signature",
          refuses(E.verify, dataclasses.replace(ent, **{field: value}), gk.public_key()))

# RFC 9180's named failure: a low-order recipient key drives the shared secret
# to a constant every reader can compute.
LOW_ORDER = {
    "all zeros": bytes(32),
    "one": bytes([1]) + bytes(31),
    "p-1 order": bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    "order 8": bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
}
for name, bad in LOW_ORDER.items():
    check(f"refuses to seal to a low-order key ({name})", refuses(E.seal, b"secret", bad))

check("refuses an entitlement that expires before it is issued",
      refuses(E.issue, b"x", pub, 1_790_000_000, 1_788_000_000, gk))
check("refuses a sealed bundle above the contract's bound",
      refuses(E.signing_message, pub, pub, bytes(12), b"x" * 9000, 1, 2, 1))
check("refuses an issuance sequence below 1",
      refuses(E.issue, b"x", pub, 1, 2, gk, 0))
check("two envelopes to one subscriber are refused by register()",
      refuses(E.register, [ent, ent]))

# ---------------------------------------------------------------------------
section("the reference")

good = f"CF1.{E.b64(pub)}.all.{E.b64(os.urandom(9))}"
one = f"CF1.{E.b64(pub)}.t3.{E.b64(os.urandom(9))}"
check("a well-formed reference yields key and sku", G.parse_reference(good) == (pub, "all"))
check("a single-title reference yields its sku", G.parse_reference(one)[1] == "t3")
check("a reference is short enough for the component", len(one) <= 128, f"{len(one)} bytes")

for label, bad in [
    ("wrong prefix", f"CF2.{E.b64(pub)}.all.aaaa"),
    ("three parts (the old format)", f"CF1.{E.b64(pub)}.aaaa"),
    ("five parts", f"CF1.{E.b64(pub)}.all.aaaa.bbbb"),
    ("empty freshness suffix", f"CF1.{E.b64(pub)}.all."),
    ("key is not base64url", "CF1.!!!!.all.aaaa"),
    ("key is the wrong length", f"CF1.{E.b64(pub[:16])}.all.aaaa"),
    ("unknown sku", f"CF1.{E.b64(pub)}.gold.aaaa"),
    ("sku that is not a number", f"CF1.{E.b64(pub)}.tx.aaaa"),
    ("longer than the component accepts", "CF1." + "A" * 200 + ".all.aaaa"),
    ("somebody else's sale reference", "AZT-1-1-4-1802"),
    ("empty", ""),
]:
    check(f"refuses a reference: {label}", refuses(G.parse_reference, bad))

check("a sku outside the catalogue grants nothing", refuses(G.titles_for, "t99"))
check("all-access grants every title", len(G.titles_for("all")) == 9)
check("one sku grants exactly one title", len(G.titles_for("t3")) == 1)

# ---------------------------------------------------------------------------
section("price")

# Named by the adversarial review: 0, 1, price-1, price, price+1.
day = G.PRICE_MICROXTR_PER_DAY
for amount, days in [(0, 0), (1, 0), (day - 1, 0), (day, 1), (day + 1, 1),
                     (day * 30, 30), (day * 30 - 1, 29)]:
    check(f"{amount:>10,} uXTR buys {days} day(s) of all-access", G.days_for(amount) == days,
          f"got {G.days_for(amount)}")
check("all-access is priced by the month", G.price_of("all") == day * 30)
check("one portrait is priced flat", G.price_of("t3") == G.PRICE_MICROXTR_PER_TITLE)
check("nine portraits cost more than a month of everything",
      G.PRICE_MICROXTR_PER_TITLE * 9 > G.price_of("all"))

# ---------------------------------------------------------------------------
section("the ledger")

tmp = Path(tempfile.mkdtemp())
G.LEDGER = tmp / "ledger.sqlite3"
G.KEYS = tmp
# Stand-in content keys, so the bundle is exercised without reading the real
# ones. The shape is what is under test here, not the secrets.
(tmp / "content-titles.json").write_text(json.dumps(
    {t["id"]: E.b64(bytes([i]) * 32) for i, t in enumerate(G.catalogue())}))
db = G.open_ledger()
now = 1_800_000_000
real_read_transaction_outcome = G.read_transaction_outcome
G.read_transaction_outcome = lambda _tx_id: G.COMMITTED


def event(event_id: int, reference: str, amount: int, tx: str = "tx"):
    return {"_id": event_id, "transaction_id": tx,
            "event": {"payload": {"sale_ref": reference, "amount": str(amount)}}}


check("a good all-access payment is credited",
      G.credit(db, event(1, good, day * 30), now) == "credited")
check("the same event replayed is a duplicate",
      G.credit(db, event(1, good, day * 30), now) == "duplicate")
sub_pub = E.b64(pub)
check("all-access grants all nine titles",
      db.execute("SELECT COUNT(*) n FROM grants WHERE subscriber = ?", (sub_pub,)).fetchone()["n"] == 9)
check("a duplicate does not extend the window",
      db.execute("SELECT expires_at FROM subscribers").fetchone()["expires_at"] == now + 30 * 86400)

check("one microXTR buys nothing", G.credit(db, event(2, good, 1), now) == "underpaid")
check("a title price does not buy all-access",
      G.credit(db, event(8, good, G.PRICE_MICROXTR_PER_TITLE), now) == "underpaid")
check("an underpayment does not extend the window",
      db.execute("SELECT expires_at FROM subscribers").fetchone()["expires_at"] == now + 30 * 86400)

check("somebody else's reference is ignored",
      G.credit(db, event(3, "AZT-1-1-4-1802", 5_000_000, "other"), now) == "ignored")
check("an ignored payment creates no subscriber",
      db.execute("SELECT COUNT(*) n FROM subscribers").fetchone()["n"] == 1)

# --- ordering ONE resource -------------------------------------------------
buyer = X25519PrivateKey.generate().public_key().public_bytes_raw()
buyer_b64 = E.b64(buyer)
one_ref = f"CF1.{buyer_b64}.t3.{E.b64(os.urandom(9))}"
check("a single portrait can be bought",
      G.credit(db, event(10, one_ref, G.PRICE_MICROXTR_PER_TITLE, "t1"), now) == "credited")
rows = db.execute("SELECT title_id, until FROM grants WHERE subscriber = ?", (buyer_b64,)).fetchall()
check("buying one portrait grants exactly one", len(rows) == 1, f"got {len(rows)}")
check("a bought portrait is kept, not rented", rows[0]["until"] == 0)
check("its title is the one that was ordered", rows[0]["title_id"] == G.titles_for("t3")[0])
check("one microXTR does not buy a portrait",
      G.credit(db, event(11, one_ref, 1, "t2"), now) == "underpaid")

# A SECOND portrait must not erase the first. This is the case that killed
# expiry-as-join-key: both purchases are perpetual, so their expiries tie.
two_ref = f"CF1.{buyer_b64}.t5.{E.b64(os.urandom(9))}"
G.credit(db, event(12, two_ref, G.PRICE_MICROXTR_PER_TITLE, "t3"), now)
check("buying a second portrait keeps the first",
      db.execute("SELECT COUNT(*) n FROM grants WHERE subscriber = ?",
                 (buyer_b64,)).fetchone()["n"] == 2)

# Renting all-access after buying one outright must not turn the bought one
# into a rental.
all_ref = f"CF1.{buyer_b64}.all.{E.b64(os.urandom(9))}"
G.credit(db, event(13, all_ref, day * 30, "t4"), now)
kept = db.execute("SELECT COUNT(*) n FROM grants WHERE subscriber = ? AND until = 0",
                  (buyer_b64,)).fetchone()["n"]
check("all-access does not downgrade a portrait already bought", kept == 2, f"got {kept}")
check("all-access still grants the other seven",
      db.execute("SELECT COUNT(*) n FROM grants WHERE subscriber = ?",
                 (buyer_b64,)).fetchone()["n"] == 9)

# --- the bundle and the join key -------------------------------------------
bundle = json.loads(G.subscriber_bundle(db, buyer_b64))
check("the bundle carries every grant", len(bundle["grants"]) == 9)
check("the bundle carries a key per title",
      all("key" in g and len(E.unb64(g["key"])) == 32 for g in bundle["grants"].values()))
check("kept titles are marked until=0 in the bundle",
      sum(1 for g in bundle["grants"].values() if g["until"] == 0) == 2)

check("every credited payment is queued for delivery",
      db.execute("SELECT COUNT(*) n FROM payments WHERE issued = 0").fetchone()["n"]
      == db.execute("SELECT COUNT(*) n FROM payments WHERE verdict = 'credited'").fetchone()["n"])
unissued = {r["verdict"] for r in db.execute("SELECT DISTINCT verdict FROM payments WHERE issued = 0")}
closed = {r["verdict"].split(":")[0] for r in db.execute("SELECT DISTINCT verdict FROM payments WHERE issued = 1")}
check("only credited payments wait to be delivered", unissued == {"credited"}, f"got {unissued}")
check("underpaid and ignored payments are closed, not queued",
      closed == {"underpaid", "ignored"}, f"got {closed}")

G.read_transaction_outcome = real_read_transaction_outcome

# ---------------------------------------------------------------------------
print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("failed: " + ", ".join(FAIL))
    raise SystemExit(1)
