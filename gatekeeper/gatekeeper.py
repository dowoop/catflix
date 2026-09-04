#!/usr/bin/env python3
"""The gatekeeper: watch the Ootle for money, write entitlements to Freenet.

## What this is, stated without flattery

This is the centralised part, and calling it anything else would be a lie. It
decides whether a payment was enough, which key gets access, and for how long.
Freenet verifies only that this process signed the result; it cannot verify
that the result corresponds to a payment.

The honest claim is narrower than "decentralised", and it is still worth
something:

    **The gatekeeper is needed to SELL. It is never needed to SERVE.**

Kill it after issuance and every existing subscriber keeps working forever --
their envelope is already in replicated Freenet state and the ciphertext is
already in the web container. No domain, no TLS certificate, no host, no
uptime. An HTTPS key service cannot say that; when it goes down, everyone is
locked out. That difference is the entire reason the entitlement lives in a
contract instead of a database.

## The five obligations, each from a defect somebody already paid for

1. **Money must name the sale.** `pay(Bucket, sale_ref)` takes the reference as
   an argument, so nothing is inferred from amount, timing or polling order.
   This workspace measured what inference costs: a 100,000 uT sale settling on
   a 5,000,000 uT payment meant for somebody else.

2. **The reference must carry the subscriber's public key, in full.** Not a
   hash of it. A hash cannot be reversed, and the gatekeeper's whole job is to
   seal a bundle TO that key -- with only a digest it has nothing to seal to,
   and would need a separate registration service to look the key up. Putting
   the key in the reference removes that service entirely. 43 base64 characters
   inside the component's own 128-byte bound.

3. **The reference must still be fresh.** A reference derived from the
   subscriber key alone repeats on every renewal, and this workspace already
   reproduced what repeated references do: a till whose database was deleted
   reissued a reference that had already been paid. So the reference carries a
   random suffix, and a fresh keypair is minted per order -- which also stops
   an observer linking one subscriber's renewals to each other on a public
   ledger.

4. **Price is enforced here or nowhere.** The component checks `amount > 0` and
   nothing else, deliberately: it has no view of any host's prices. So one
   microXTR buys a full subscription unless this file refuses it. Access is
   granted in whole days actually paid for, and a payment below one day buys
   nothing and is recorded as underpaid.

5. **A payment credited but not issued must be issued on restart.** Crediting
   and issuing are two steps and a process can die between them. So the ledger
   records the credit with `issued = 0` and every start sweeps for those. A
   subscription that has been paid for and never delivered is the one failure
   here that takes somebody's money and gives them nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import envelope as E

ROOT = Path(__file__).resolve().parents[1]

# `keys/` holds things whose loss cannot be undone: the signing key (its public
# half IS the contract's address), the content keys, the ledger, and every
# order key a buyer was handed. `run/` holds files regenerated on the next
# sweep. They were one directory until somebody had to be told which of
# twenty-five files were safe to delete -- which is a question nobody should
# have to ask about a directory containing a private key.
KEYS = ROOT / "keys"
RUN = ROOT / "run"
LEDGER = KEYS / "ledger.sqlite3"

INDEXER = "https://ootle-indexer-a.tari.com"
COMPONENT = "component_a2208e00baa392cd1a6d6ef8336e083fac01499ec19dacde0f245114f0f37aab"
TOPIC = "Payments.PaymentReceived"

# The tariff. In microXTR, the unit the event stream reports.
#
# Two things are for sale and they are priced on different axes on purpose: a
# single portrait is BOUGHT (once, kept), all-access is RENTED (by the day).
# Nine portraits bought one at a time cost more than a month of everything,
# which is the right way round -- otherwise nobody would ever rent.
PRICE_MICROXTR_PER_DAY = 250_000        # all-access, per day
PRICE_MICROXTR_PER_TITLE = 1_000_000    # one portrait, kept
DAY_SECONDS = 86_400

# What "kept" means to a lattice that has no clock: a date far enough out that
# comparing against it is always the same answer. 2100-01-01.
PERPETUAL = 4_102_444_800

ALL_ACCESS = "all"

REFERENCE_PREFIX = "CF1"
# The component refuses a reference over 128 bytes. Ours is ~60; this is the
# bound a MALFORMED one is measured against before anything parses it.
MAX_REFERENCE = 128

# Indexer replies are protocol messages, not an invitation for the remote end
# to choose this process's memory use. This is the same ceiling used by the
# published Ootle rail.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

#: The longest a single read may block. See `read_events`: this is a slice of
#: the caller's timeout rather than the whole of it, so the wall-clock deadline
#: there is enforced instead of merely stated. Five seconds because esmeralda
#: answers a live replay in under one -- measured at 4.56s for five events over
#: a cold connection on 2026-08-31, and well under that warm.
READ_SLICE_SECONDS = 5

#: The most the house will EVER spend covering strangers, in microXTR, across
#: the whole life of the ledger.
#:
#: `cover --max` bounds ONE SWEEP and `./catflix serve` sweeps forever, so until
#: this existed the only limit on house spending was how long the seller was
#: left running. The queue contract is unsigned and grow-only by design -- that
#: is what lets a visitor with no wallet ask at all -- so anyone can append
#: fresh, valid, unpaid references indefinitely and collect `--max` portraits
#: every interval. At the default two per 15s sweep and 1,000,000 uXTR a
#: portrait that is about 11,520 XTR a day, which is faucet capacity rather than
#: money, and is still the wrong thing for a reference implementation to teach.
#:
#: 60,000,000 uXTR is sixty portraits, or two months of all-access. Enough that
#: an ordinary demo never notices it; small enough that a drain stops.
HOUSE_BUDGET_MICROXTR = 60_000_000

COMMITTED = "Commit"


class Refusal(Exception):
    """A payment this gatekeeper will not act on, with the reason it gives."""


class UnresolvedTransaction(Exception):
    """The indexer did not provide a transaction outcome we can decide on."""


# --------------------------------------------------------------------------
# the ledger
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

-- Keyed on the indexer's event id, which is the finest identity a payment
-- has. Keying on the transaction id instead would silently merge two `pay`
-- calls made in one transaction -- legal, and it would credit one of them.
CREATE TABLE IF NOT EXISTS payments (
    event_id     INTEGER PRIMARY KEY,
    tx_id        TEXT    NOT NULL,
    sale_ref     TEXT    NOT NULL,
    amount       INTEGER NOT NULL,
    subscriber   TEXT,
    verdict      TEXT    NOT NULL,
    days         INTEGER NOT NULL DEFAULT 0,
    seen_at      INTEGER NOT NULL,
    issued       INTEGER NOT NULL DEFAULT 0,
    issued_at    INTEGER
);

CREATE TABLE IF NOT EXISTS subscribers (
    subscriber  TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL,
    total_paid  INTEGER NOT NULL,
    -- The contract's join key. Every issuance to this subscriber bumps it, and
    -- the newest issuance carries their whole set of grants, so "highest seq
    -- wins" is a superset rather than a replacement.
    seq         INTEGER NOT NULL DEFAULT 0
);

-- One row per title this subscriber may open. `until = 0` means bought
-- outright and kept; anything else is a rental deadline. Rows are only ever
-- extended, never revoked: taking back a portrait somebody paid for would be
-- theft, and the contract could not enforce it anyway.
CREATE TABLE IF NOT EXISTS grants (
    subscriber TEXT NOT NULL,
    title_id   TEXT NOT NULL,
    until      INTEGER NOT NULL,
    PRIMARY KEY (subscriber, title_id)
);

CREATE INDEX IF NOT EXISTS payments_unissued ON payments (issued) WHERE issued = 0;

-- Every reference the house has paid for somebody, keyed on the reference so
-- a second sweep over a queue that still contains it cannot pay it again. The
-- queue contract is grow-only: a covered reference stays in it forever, and
-- "have I already done this?" is a question only this table can answer.
CREATE TABLE IF NOT EXISTS covered (
    sale_ref   TEXT PRIMARY KEY,
    amount     INTEGER NOT NULL,
    tx_id      TEXT,
    outcome    TEXT NOT NULL,
    covered_at INTEGER NOT NULL
);
"""


def open_ledger() -> sqlite3.Connection:
    KEYS.mkdir(exist_ok=True)
    RUN.mkdir(exist_ok=True)
    db = sqlite3.connect(LEDGER)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)

    # `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists,
    # so a ledger written before titles became separately purchasable opens
    # cleanly and then fails on the first query for a column it does not have.
    # Detect that here and say what to do, rather than surfacing it later as a
    # sqlite error in the middle of crediting somebody's payment.
    columns = {r["name"] for r in db.execute("PRAGMA table_info(subscribers)")}
    if columns and "seq" not in columns:
        raise SystemExit(
            f"{LEDGER} was written by a build before per-title ordering, and its\n"
            "format is not compatible: references had three parts, bundles were keyed\n"
            "by epoch, and the contract those entitlements live in has a different\n"
            "address now. Archive it and start clean:\n\n"
            f"    mv {LEDGER} {LEDGER}.pre-sku\n"
        )
    return db


def cursor(db: sqlite3.Connection) -> int:
    row = db.execute("SELECT v FROM meta WHERE k = 'cursor'").fetchone()
    return int(row["v"]) if row else 0


def set_cursor(db: sqlite3.Connection, value: int) -> None:
    db.execute(
        "INSERT INTO meta (k, v) VALUES ('cursor', ?) "
        "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        (str(value),),
    )


# --------------------------------------------------------------------------
# the reference
# --------------------------------------------------------------------------

def parse_reference(sale_ref: str) -> tuple[bytes, str]:
    """`CF1.<43 chars of X25519 key>.<sku>.<freshness>` -> (key, sku).

    The SKU is in the reference because the money has to say WHAT it is buying,
    and the only channel between a payer and this process is the reference. The
    alternative -- inferring the purchase from the amount -- is the same
    inference this whole project exists to delete.

    Every refusal is a refusal and not a repair. A reference this cannot read
    is somebody else's payment to the same component (it is shared, and takes
    anyone's money), and guessing would credit a stranger's sale to a cat.
    """
    if len(sale_ref) > MAX_REFERENCE:
        raise Refusal("reference longer than the component accepts")
    parts = sale_ref.split(".")
    if len(parts) != 4 or parts[0] != REFERENCE_PREFIX:
        raise Refusal("not a catflix reference")
    if not parts[3]:
        raise Refusal("reference carries no freshness suffix")
    try:
        key = E.unb64(parts[1])
    except Exception:
        raise Refusal("subscriber key is not base64url") from None
    if len(key) != 32:
        raise Refusal(f"subscriber key is {len(key)} bytes, not 32")
    sku = parts[2]
    #   all        every portrait, rented by the day
    #   tN         one portrait, kept
    #   mN N N...  a basket of portraits, kept, paid for in one transaction
    ok = (sku == ALL_ACCESS
          or (sku.startswith("t") and sku[1:].isdigit())
          or (sku.startswith("m") and len(sku) > 1 and sku[1:].isdigit()))
    if not ok:
        raise Refusal(f"unknown sku {sku!r}")
    return key, sku


def days_for(amount_microxtr: int) -> int:
    """Whole days of all-access actually paid for. Never rounds up."""
    return amount_microxtr // PRICE_MICROXTR_PER_DAY


def price_of(sku: str) -> int:
    """What this SKU costs. The component enforces none of this; here or nowhere."""
    if sku == ALL_ACCESS:
        return PRICE_MICROXTR_PER_DAY * 30
    if sku.startswith("m"):
        # A basket is priced per portrait in it, counted from the DEDUPED set --
        # `m333` is one portrait, not three, and charging for three would take
        # money for something already granted.
        return PRICE_MICROXTR_PER_TITLE * len(set(sku[1:]))
    return PRICE_MICROXTR_PER_TITLE


def catalogue() -> list[dict]:
    path = ROOT / "site" / "catalog.json"
    if not path.exists():
        raise SystemExit("no site/catalog.json; run catalog/build.py first")
    return json.loads(path.read_text())["titles"]


def titles_for(sku: str) -> list[str]:
    """Which title ids a SKU grants. Unknown SKUs grant nothing, loudly."""
    entries = catalogue()
    if sku == ALL_ACCESS:
        return [t["id"] for t in entries]

    if sku.startswith("m"):
        by_sku = {t["sku"]: t["id"] for t in entries}
        # Sorted and deduped, so `m30` and `m03` and `m300` are one basket and
        # one price. Two references that mean the same thing must not be able
        # to grant different sets.
        wanted = sorted(set(sku[1:]))
        missing = [d for d in wanted if f"t{d}" not in by_sku]
        if missing or not wanted:
            raise Refusal(f"basket {sku!r} names portraits that are not in the catalogue")
        return [by_sku[f"t{d}"] for d in wanted]

    match = [t["id"] for t in entries if t["sku"] == sku]
    if not match:
        raise Refusal(f"sku {sku!r} is not in the catalogue")
    return match


# --------------------------------------------------------------------------
# reading the chain
# --------------------------------------------------------------------------

def read_events(after_id: int, timeout: int = 30) -> list[dict]:
    """One page of `Payments.PaymentReceived`, replayed from a cursor.

    Server-sent events over plain HTTP GET. Parsed here rather than through
    the rail's reader because this wants every event on the component, not the
    subset naming one sale -- the rail answers "was THIS sale paid?", and the
    question here is "what has anyone paid?".
    """
    url = (
        f"{INDEXER}/transactions/events/stream"
        f"?substate_id={COMPONENT}&topic={TOPIC}&after_id={after_id}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "catflix-gatekeeper/0.1"})

    # THIS ENDPOINT DOES NOT END. Read one bounded replay and treat a socket
    # timeout after connecting as its end. A comment is not an end marker in
    # SSE: it is legal before, between, or inside the backlog, so stopping at
    # one can silently skip a payment.
    events = []
    data_lines: list[str] = []
    event_id_text: str | None = None
    last_id = after_id
    response_bytes = 0
    deadline = time.monotonic() + timeout

    def dispatch() -> None:
        nonlocal data_lines, event_id_text, last_id
        if not data_lines:
            event_id_text = None
            return
        if event_id_text is None or not event_id_text.isdecimal():
            raise ValueError("event stream frame had no non-negative decimal id")
        event_id = int(event_id_text)
        if event_id <= last_id:
            raise ValueError("event stream ids were not strictly increasing after the cursor")
        try:
            payload = json.loads("\n".join(data_lines))
        except json.JSONDecodeError as exc:
            raise ValueError(f"event stream data was not JSON: {exc}") from None
        if not isinstance(payload, dict):
            raise ValueError("event stream data was not a JSON object")
        payload["_id"] = event_id
        events.append(payload)
        last_id = event_id
        data_lines = []
        event_id_text = None

    # THE PER-READ TIMEOUT IS A SLICE OF THE BUDGET, NOT THE WHOLE OF IT, and
    # that is what makes the deadline below real. `urlopen(timeout=...)` bounds
    # each recv, not a `readline`: a server that sends one byte every
    # `timeout - 1` seconds resets the clock on every recv and never completes
    # the line, so a single `readline` can outlive any wall-clock deadline
    # checked before it. The byte ceiling still holds -- but 4 MiB trickled a
    # byte at a time is years, so the memory bound was doing all the work and
    # the time bound was a sentence. Slicing it means the worst overshoot past
    # the deadline is one `READ_SLICE_SECONDS`, which is a bound rather than a
    # hope.
    #
    # A slow-but-honest indexer that needs longer than one slice to produce the
    # next line is treated as the end of the replay. That is safe here for the
    # reason the published Ootle rail gives about the same situation: the events
    # are cursor-addressed, so a short read is a SHORTER answer, not a partial
    # one -- the next poll resumes from the last id seen and nothing is skipped.
    with urllib.request.urlopen(request, timeout=READ_SLICE_SECONDS) as response:
        while time.monotonic() <= deadline:
            try:
                raw = response.readline(MAX_RESPONSE_BYTES + 1 - response_bytes)
            except OSError:
                # The connection was established. Esmeralda holds an idle SSE
                # response open, so its read timeout is the normal replay end.
                break
            response_bytes += len(raw)
            if response_bytes > MAX_RESPONSE_BYTES:
                raise ValueError(
                    f"indexer event response exceeded {MAX_RESPONSE_BYTES} bytes"
                )
            if not raw:
                break
            try:
                line = raw.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as exc:
                raise ValueError(f"event stream was not UTF-8: {exc}") from None
            if line == "":
                dispatch()
                continue
            if line.startswith(":"):
                continue

            field, separator, value = line.partition(":")
            if not separator:
                value = ""
            elif value.startswith(" "):
                value = value[1:]
            if field == "data":
                data_lines.append(value)
            elif field == "id":
                event_id_text = value
        # Accept a complete final frame even if a finite test server closes
        # without the optional trailing blank line. A partial JSON frame fails
        # closed, leaving the cursor untouched so the next read replays it.
        if data_lines:
            dispatch()
    return events


def read_transaction_outcome(transaction_id: str, timeout: int = 30) -> str:
    """Return the indexer's explicit outcome, or raise while it is unknown.

    Only an explicit ``Commit`` permits disclosure. An explicit other outcome
    is a refusal. Transport failures, oversized replies, malformed JSON, and a
    reply for a different transaction are unresolved: none is evidence that
    the transaction aborted, and the caller must persist and retry the event.
    """
    if not isinstance(transaction_id, str) or not transaction_id:
        raise UnresolvedTransaction("transaction id was not non-empty text")
    encoded = urllib.parse.quote(transaction_id, safe="")
    request = urllib.request.Request(
        f"{INDEXER}/transactions/{encoded}",
        headers={"User-Agent": "catflix-gatekeeper/0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise UnresolvedTransaction(
                f"transaction response exceeded {MAX_RESPONSE_BYTES} bytes"
            )
        body = json.loads(raw.decode("utf-8"))
    except UnresolvedTransaction:
        raise
    except urllib.error.HTTPError as exc:
        raise UnresolvedTransaction(f"indexer answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise UnresolvedTransaction(f"indexer did not answer: {exc}") from None
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise UnresolvedTransaction(f"indexer transaction reply was not JSON: {exc}") from None

    transaction = body.get("transaction") if isinstance(body, dict) else None
    if not isinstance(transaction, dict):
        raise UnresolvedTransaction("indexer transaction reply had an unknown shape")
    if transaction.get("transaction_id") != transaction_id:
        raise UnresolvedTransaction("indexer answered with a different transaction")
    summary = transaction.get("summary")
    outcome = summary.get("outcome") if isinstance(summary, dict) else None
    if not isinstance(outcome, str) or not outcome:
        raise UnresolvedTransaction("indexer transaction reply had no outcome")
    return outcome


# --------------------------------------------------------------------------
# crediting
# --------------------------------------------------------------------------

def credit(db: sqlite3.Connection, event: dict, now: int) -> str:
    """Record one payment event. Returns a one-word verdict.

    Idempotent on the event id: replaying the whole stream from zero against a
    populated ledger changes nothing, which is what makes a restored backup or
    a re-read cursor safe.
    """
    event_id = event["_id"]
    existing_payment = db.execute(
        "SELECT * FROM payments WHERE event_id = ?", (event_id,)
    ).fetchone()
    if existing_payment is not None and existing_payment["verdict"] != "unresolved":
        return "duplicate"

    if existing_payment is None:
        payload = event["event"]["payload"]
        sale_ref = payload["sale_ref"]
        amount = int(payload["amount"])
        tx_id = event["transaction_id"]
    else:
        # Once persisted, the first sighting is authoritative. A replay whose
        # body changed must not be able to change what this event purchases.
        sale_ref = existing_payment["sale_ref"]
        amount = existing_payment["amount"]
        tx_id = existing_payment["tx_id"]

    try:
        key, sku = parse_reference(sale_ref)
        titles = titles_for(sku)
    except Refusal as refusal:
        db.execute(
            "INSERT INTO payments (event_id, tx_id, sale_ref, amount, subscriber, verdict, seen_at, issued)"
            " VALUES (?,?,?,?,NULL,?,?,1)",
            (event_id, tx_id, sale_ref, amount, f"ignored: {refusal}", now),
        )
        return "ignored"

    subscriber = E.b64(key)
    try:
        outcome = read_transaction_outcome(tx_id)
    except UnresolvedTransaction:
        if existing_payment is None:
            db.execute(
                "INSERT INTO payments "
                "(event_id, tx_id, sale_ref, amount, subscriber, verdict, days, seen_at, issued) "
                "VALUES (?,?,?,?,?,'unresolved',0,?,0)",
                (event_id, tx_id, sale_ref, amount, subscriber, now),
            )
        return "unresolved"

    if outcome != COMMITTED:
        verdict = f"refused: transaction outcome {outcome!r}"
        if existing_payment is None:
            db.execute(
                "INSERT INTO payments "
                "(event_id, tx_id, sale_ref, amount, subscriber, verdict, days, seen_at, issued) "
                "VALUES (?,?,?,?,NULL,?,0,?,1)",
                (event_id, tx_id, sale_ref, amount, verdict, now),
            )
        else:
            db.execute(
                "UPDATE payments SET subscriber = NULL, verdict = ?, days = 0, issued = 1 "
                "WHERE event_id = ?",
                (verdict, event_id),
            )
        return "refused"

    if amount < price_of(sku):
        # OBLIGATION 4. The component accepted this and was right to; a
        # component that judged prices would be a component that had to know
        # every host's prices. Refusing here is where it belongs.
        if existing_payment is None:
            db.execute(
                "INSERT INTO payments "
                "(event_id, tx_id, sale_ref, amount, subscriber, verdict, days, seen_at, issued)"
                " VALUES (?,?,?,?,?,?,0,?,1)",
                (event_id, tx_id, sale_ref, amount, subscriber, "underpaid", now),
            )
        else:
            db.execute(
                "UPDATE payments SET verdict = 'underpaid', days = 0, issued = 1 "
                "WHERE event_id = ?",
                (event_id,),
            )
        return "underpaid"

    row = db.execute(
        "SELECT expires_at, total_paid FROM subscribers WHERE subscriber = ?", (subscriber,)
    ).fetchone()

    if sku == ALL_ACCESS:
        days = days_for(amount)
        # A renewal EXTENDS from the later of now and the current deadline, so
        # renewing early does not throw away time already bought.
        base = max(now, row["expires_at"]) if row and row["expires_at"] < PERPETUAL else now
        until = base + days * DAY_SECONDS
    else:
        days = 0
        until = 0  # bought outright

    for title_id in titles:
        existing = db.execute(
            "SELECT until FROM grants WHERE subscriber = ? AND title_id = ?",
            (subscriber, title_id),
        ).fetchone()
        if existing is not None:
            # Never downgrade. A rental must not shorten a title already
            # bought outright, and a shorter rental must not shorten a longer.
            if existing["until"] == 0:
                continue
            until_for_row = 0 if until == 0 else max(existing["until"], until)
        else:
            until_for_row = until
        db.execute(
            "INSERT INTO grants (subscriber, title_id, until) VALUES (?,?,?) "
            "ON CONFLICT(subscriber, title_id) DO UPDATE SET until = excluded.until",
            (subscriber, title_id, until_for_row),
        )

    total = (row["total_paid"] if row else 0) + amount
    horizon = db.execute(
        "SELECT MAX(CASE WHEN until = 0 THEN ? ELSE until END) h FROM grants WHERE subscriber = ?",
        (PERPETUAL, subscriber),
    ).fetchone()["h"] or now
    db.execute(
        "INSERT INTO subscribers (subscriber, expires_at, total_paid, seq) VALUES (?,?,?,0) "
        "ON CONFLICT(subscriber) DO UPDATE SET expires_at = excluded.expires_at, "
        "total_paid = excluded.total_paid",
        (subscriber, horizon, total),
    )
    if existing_payment is None:
        db.execute(
            "INSERT INTO payments "
            "(event_id, tx_id, sale_ref, amount, subscriber, verdict, days, seen_at, issued)"
            " VALUES (?,?,?,?,?,?,?,?,0)",
            (event_id, tx_id, sale_ref, amount, subscriber, "credited", days, now),
        )
    else:
        db.execute(
            "UPDATE payments SET subscriber = ?, verdict = 'credited', days = ?, issued = 0 "
            "WHERE event_id = ?",
            (subscriber, days, event_id),
        )
    return "credited"


def retry_unresolved(db: sqlite3.Connection, now: int) -> list[str]:
    """Re-read every persisted event whose transaction outcome was unavailable."""
    verdicts = []
    rows = db.execute(
        "SELECT event_id FROM payments WHERE verdict = 'unresolved' ORDER BY event_id"
    ).fetchall()
    for row in rows:
        verdicts.append(credit(db, {"_id": row["event_id"]}, now))
    return verdicts


# --------------------------------------------------------------------------
# issuing
# --------------------------------------------------------------------------

def title_keys() -> dict:
    path = KEYS / "content-titles.json"
    if not path.exists():
        raise SystemExit("no content keys; run catalog/build.py first")
    return json.loads(path.read_text())


def subscriber_bundle(db: sqlite3.Connection, subscriber: str) -> bytes:
    """Everything this subscriber has ever bought, sealed in one envelope.

    CUMULATIVE, and that is the whole reason it is safe for the contract to
    keep only the newest issuance per subscriber. A bundle that carried just
    the latest purchase would make buying a second portrait erase the first.
    """
    keys = title_keys()
    grants = {}
    for row in db.execute(
        "SELECT title_id, until FROM grants WHERE subscriber = ? ORDER BY title_id", (subscriber,)
    ):
        key = keys.get(row["title_id"])
        if key is None:
            continue  # a title that left the catalogue; nothing to hand over
        grants[row["title_id"]] = {"key": key, "until": row["until"]}
    return json.dumps({"v": 2, "grants": grants}, separators=(",", ":")).encode()


def signing_key() -> Ed25519PrivateKey:
    path = KEYS / "gatekeeper.ed25519"
    if not path.exists():
        raise SystemExit("no gatekeeper key; run `gatekeeper.py init` first")
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def issue_pending(db: sqlite3.Connection, contract: str | None, epoch: int, now: int,
                  ports: list[int] | None = None) -> int:
    """OBLIGATION 5. Everything credited and not yet delivered.

    Runs on every start and after every poll, so a crash between crediting and
    issuing costs a restart rather than a subscription.
    """
    ports = ports or [7509]
    pending = db.execute(
        "SELECT DISTINCT subscriber FROM payments "
        "WHERE verdict = 'credited' AND issued = 0 AND subscriber IS NOT NULL"
    ).fetchall()
    if not pending:
        return 0

    gk = signing_key()
    entitlements = []
    for row in pending:
        subscriber = row["subscriber"]
        record = db.execute(
            "SELECT expires_at, seq FROM subscribers WHERE subscriber = ?", (subscriber,)
        ).fetchone()
        # The join key rises here and nowhere else, so two issuances to one
        # subscriber can never tie and leave the network picking on signature
        # bytes.
        seq = record["seq"] + 1
        db.execute("UPDATE subscribers SET seq = ? WHERE subscriber = ?", (seq, subscriber))
        entitlements.append(
            E.issue(subscriber_bundle(db, subscriber), E.unb64(subscriber),
                    now, record["expires_at"], gk, seq=seq)
        )

    delta = E.register(entitlements)
    if contract:
        push_delta(contract, delta, ports)
    else:
        print("  (no contract key configured -- delta written to keys/pending-delta.json only)")
    (RUN / "pending-delta.json").write_text(json.dumps(delta, separators=(",", ":")))

    db.execute(
        "UPDATE payments SET issued = 1, issued_at = ? "
        "WHERE verdict = 'credited' AND issued = 0 AND subscriber IS NOT NULL",
        (now,),
    )
    return len(entitlements)


def push_delta(contract: str, delta: dict, ports: list[int]) -> None:
    """Hand the delta to every node that serves readers.

    EVERY node, because an entitlement is only useful in the node the buyer's
    browser is talking to. Running a private node for development and a
    separate throwaway one behind a domain means two places a reader can be,
    and issuing to one of them would leave the other's visitors staring at a
    locked page after paying.

    A delta and not a full state: `update_state` joins, so sending only what
    changed is both smaller and safer.
    """
    RUN.mkdir(exist_ok=True)
    path = RUN / "delta.json"
    path.write_text(json.dumps(delta, separators=(",", ":")))
    failures = []
    for port in ports:
        result = subprocess.run(
            ["fdev", "-p", str(port), "execute", "update", contract, str(path)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            failures.append(f"  port {port}: {result.stderr.strip()[-400:]}")
    # Refuse only if EVERY node refused. One node being down must not stop a
    # paying customer being served by the others -- and the sweep will retry
    # the rest on the next pass, because `issued` only clears on success.
    if len(failures) == len(ports):
        raise SystemExit("no node accepted the update:\n" + "\n".join(failures))
    for line in failures:
        print(f"  WARNING a node refused the update, others took it\n{line}")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_init(args) -> None:
    KEYS.mkdir(exist_ok=True)
    path = KEYS / "gatekeeper.ed25519"
    if path.exists() and not args.force:
        raise SystemExit(f"{path} exists; --force to replace it (this abandons every issued envelope)")
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes_raw())
    path.chmod(0o600)
    params = KEYS / "params.bin"
    params.write_bytes(key.public_key().public_bytes_raw())
    print(f"gatekeeper key  -> {path}")
    print(f"contract params -> {params}  ({E.b64(key.public_key().public_bytes_raw())})")
    print("\nThe public key IS the contract's parameters, and parameters are part of")
    print("the contract address. Replacing this key produces a different contract at a")
    print("different address; it does not re-key the existing one.")


def cmd_watch(args) -> None:
    db = open_ledger()
    now = int(time.time())

    # The sweep first, before reading a single new event. A restart is the
    # commonest way to arrive here holding undelivered credit.
    swept = issue_pending(db, args.contract, args.epoch, now, args.node_port)
    if swept:
        print(f"swept {swept} entitlement(s) credited but never issued")
    db.commit()

    while True:
        at = cursor(db)
        now = int(time.time())
        counts: dict[str, int] = {}
        for verdict in retry_unresolved(db, now):
            counts[verdict] = counts.get(verdict, 0) + 1
        try:
            events = read_events(at)
        except Exception as exc:
            # Transaction reads and the event stream are independent indexer
            # requests. A recovered transaction must still be delivered even
            # when this particular stream read fails.
            issued = issue_pending(db, args.contract, args.epoch, now, args.node_port)
            db.commit()
            if counts or issued:
                summary = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
                print(f"[{time.strftime('%H:%M:%S')}] cursor {at}->{at}  {summary}"
                      + (f"  issued {issued}" if issued else ""))
            print(f"indexer unavailable ({type(exc).__name__}: {exc}); retrying")
            if args.once:
                return
            time.sleep(args.interval)
            continue

        highest = at
        for event in events:
            verdict = credit(db, event, now)
            counts[verdict] = counts.get(verdict, 0) + 1
            highest = max(highest, event["_id"])

        issued = issue_pending(db, args.contract, args.epoch, now, args.node_port)
        # The cursor moves LAST and in the same transaction as the issuance.
        # Advancing it before delivering would turn a crash into a payment
        # that is never seen again.
        set_cursor(db, highest)
        db.commit()

        if counts or issued:
            summary = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
            print(f"[{time.strftime('%H:%M:%S')}] cursor {at}->{highest}  {summary or 'nothing new'}"
                  + (f"  issued {issued}" if issued else ""))
        if args.once:
            return
        time.sleep(args.interval)


def read_queue(contract: str, ports: list[int]) -> list[str]:
    """The references visitors have asked the house to pay, from every node.

    Unioned across nodes: a visitor writes their request to whichever node
    served them the page, and reading only one would silently ignore everybody
    who arrived by the other door.
    """
    RUN.mkdir(exist_ok=True)
    refs: set[str] = set()
    reachable = 0
    for port in ports:
        out = RUN / f"queue-{port}.json"
        result = subprocess.run(
            ["fdev", "-p", str(port), "execute", "get", contract, "-o", str(out)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            continue
        reachable += 1
        body = out.read_text() if out.exists() else ""
        if body.strip():
            refs.update(json.loads(body).get("refs", []))
    if not reachable:
        raise SystemExit("no node could be read for the request queue")
    return sorted(refs)


def cmd_cover(args) -> None:
    """Pay for visitors who asked, up to a cap, and never the same one twice.

    TWO CAPS, AND ONE OF THEM WAS MISSING. This queue is unsigned and anyone may
    append to it, which is what lets a stranger with no wallet ask at all. The
    house's protection was never that the queue is trustworthy.

    `--max` bounds ONE SWEEP. That is what this docstring used to claim was the
    whole protection -- "the house chooses, every sweep, how many strangers it
    feels like paying for" -- which is true of a sweep and false of a seller left
    running, because `./catflix serve` sweeps forever. `--budget` is the
    cumulative half, read from the ledger so a restart does not reset it.
    """
    db = open_ledger()
    now = int(time.time())

    paid_already = {r["sale_ref"] for r in db.execute("SELECT sale_ref FROM covered").fetchall()}
    seen_paid = {r["sale_ref"] for r in
                 db.execute("SELECT sale_ref FROM payments WHERE verdict = 'credited'").fetchall()}

    wanted = []
    for reference in read_queue(args.queue, args.node_port):
        if reference in paid_already or reference in seen_paid:
            continue
        try:
            _, sku = parse_reference(reference)   # the queue bounds the SHAPE; this the CONTENT
            titles_for(sku)
        except Refusal:
            continue
        wanted.append(reference)

    if not wanted:
        print("nothing in the queue that has not already been paid")
        return
    # THE CUMULATIVE CEILING, and it is checked against the ledger rather than
    # counted in this process, so restarting the seller does not reset it.
    spent = db.execute(
        "SELECT COALESCE(SUM(amount), 0) AS t FROM covered WHERE outcome = 'paid'"
    ).fetchone()["t"]
    budget = args.budget
    if spent >= budget:
        print(f"house budget exhausted: {spent:,} of {budget:,} uXTR already covered."
              f" Raise --budget deliberately, or stop covering.")
        return
    print(f"{len(wanted)} unpaid request(s); covering at most {args.max};"
          f" {spent:,} of {budget:,} uXTR spent")

    for reference in wanted[: args.max]:
        # The price is read from the reference, not from a flag: the visitor
        # chose what to order and the house pays for THAT, not for whatever
        # this sweep happened to be invoked with.
        amount = price_of(parse_reference(reference)[1])
        # PER PAYMENT, not just per sweep: the ceiling must not be crossed by
        # the last order in a sweep that started under it.
        if spent + amount > budget:
            print(f"  skipped {reference[:36]}...  {amount:,} uXTR would exceed"
                  f" the {budget:,} uXTR house budget ({spent:,} spent)")
            continue
        result = subprocess.run(
            [sys.executable, str(args.wallet), "pay", args.agent, COMPONENT, str(amount), reference],
            capture_output=True, text=True, timeout=600, cwd=str(Path(args.wallet).parent),
        )
        tx = None
        for line in result.stdout.splitlines():
            if "tx_id" in line:
                tx = line.split()[-1]
        outcome = "paid" if result.returncode == 0 else "refused"
        db.execute(
            "INSERT OR REPLACE INTO covered (sale_ref, amount, tx_id, outcome, covered_at)"
            " VALUES (?,?,?,?,?)",
            (reference, amount if outcome == "paid" else 0, tx, outcome, now),
        )
        if outcome == "paid":
            spent += amount
        db.commit()
        print(f"  {outcome:8} {reference[:36]}...  {tx or result.stderr.strip()[:70]}")


def cmd_status(args) -> None:
    db = open_ledger()
    now = int(time.time())
    print(f"cursor        {cursor(db)}")
    print(f"tariff        {PRICE_MICROXTR_PER_TITLE:,} uXTR a portrait (kept)"
          f"   |   {PRICE_MICROXTR_PER_DAY*30:,} uXTR all-access for 30 days")
    rows = db.execute("SELECT verdict, COUNT(*) n, SUM(amount) amt FROM payments GROUP BY verdict").fetchall()
    print("\npayments seen")
    for row in rows or []:
        v = row["verdict"].split(":")[0]
        print(f"  {v:<12} {row['n']:>4}   {row['amt'] or 0:>14,} uXTR")
    unissued = db.execute("SELECT COUNT(*) n FROM payments WHERE issued = 0").fetchone()["n"]
    print(f"\nundelivered   {unissued}" + ("  <-- these owe somebody a subscription" if unissued else ""))
    cov = db.execute("SELECT outcome, COUNT(*) n, SUM(amount) amt FROM covered GROUP BY outcome").fetchall()
    if cov:
        print("\ncovered by the house")
        for row in cov:
            print(f"  {row['outcome']:<10} {row['n']:>4}   {row['amt'] or 0:>14,} uXTR")

    subs = db.execute("SELECT * FROM subscribers ORDER BY expires_at DESC").fetchall()
    print(f"\nsubscribers   {len(subs)}")
    for row in subs[:20]:
        held = db.execute(
            "SELECT COUNT(*) n, SUM(until = 0) kept FROM grants WHERE subscriber = ?",
            (row["subscriber"],)).fetchone()
        window = "kept" if row["expires_at"] >= PERPETUAL else (
            f"{(row['expires_at'] - now) / DAY_SECONDS:+.1f}d")
        print(f"  {row['subscriber'][:16]}...  {held['n']} title(s), {held['kept'] or 0} kept"
              f"   {window:>8}   paid {row['total_paid']:>12,} uXTR  seq {row['seq']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="mint the gatekeeper signing key")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("watch", help="read the chain, credit, and issue")
    p.add_argument("--node-port", type=int, action="append", default=None,
                   help="a Freenet node to serve (repeatable; default 7509)")
    p.add_argument("--contract", help="Freenet contract key to update")
    p.add_argument("--epoch", type=int, default=1)
    p.add_argument("--interval", type=int, default=20)
    p.add_argument("--once", action="store_true", help="one pass, then exit")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("cover", help="pay for visitors who asked, up to a cap")
    p.add_argument("--node-port", type=int, action="append", default=None,
                   help="a Freenet node to serve (repeatable; default 7509)")
    p.add_argument("--queue", required=True, help="the request queue contract key")
    p.add_argument("--budget", type=int, default=HOUSE_BUDGET_MICROXTR,
                   help="most the house will EVER spend covering strangers, in microXTR,"
                        " measured across the whole ledger and not per sweep")
    p.add_argument("--agent", default="catflix-e2e", help="agent_wallet identity that pays")
    p.add_argument(
        "--wallet",
        default="~/Workstation/Business/Point of Sale/agent_wallet.py",
        help="path to agent_wallet.py",
    )
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--max", type=int, default=2, help="how many strangers to pay for this sweep")
    p.set_defaults(func=cmd_cover)

    p = sub.add_parser("status", help="what the ledger holds")
    p.set_defaults(func=cmd_status)

    args = parser.parse_args()
    if getattr(args, "node_port", None) is None and hasattr(args, "node_port"):
        args.node_port = [7509]
    args.func(args)


if __name__ == "__main__":
    main()
