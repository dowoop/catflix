"""Regressions at the irreversible payment-to-key boundary.

Every indexer response is an in-memory file. These tests never open a socket.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gatekeeper"))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import envelope as E
import gatekeeper as G


class Response:
    def __init__(self, body: bytes):
        self.stream = io.BytesIO(body)
        self.bytes_read = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def readline(self, size: int = -1) -> bytes:
        answer = self.stream.readline(size)
        self.bytes_read += len(answer)
        return answer

    def read(self, size: int = -1) -> bytes:
        answer = self.stream.read(size)
        self.bytes_read += len(answer)
        return answer


def payment_body(transaction_id: str = "tx") -> bytes:
    return json.dumps({
        "transaction_id": transaction_id,
        "event": {"payload": {"sale_ref": "unused", "amount": "1"}},
    }, separators=(",", ":")).encode()


def frame(event_id: int, body: bytes | None = None) -> bytes:
    return f"id: {event_id}\n".encode() + b"data: " + (body or payment_body()) + b"\n\n"


class EventStreamTests(unittest.TestCase):
    def read(self, body: bytes, after_id: int = 0):
        response = Response(body)
        with patch("urllib.request.urlopen", return_value=response):
            return G.read_events(after_id, timeout=1), response

    def test_optional_spaces_after_colons(self):
        events, _ = self.read(b"id:7\ndata:" + payment_body() + b"\n\n")
        self.assertEqual([event["_id"] for event in events], [7])

    def test_fields_may_put_data_before_id(self):
        events, _ = self.read(b"data: " + payment_body() + b"\nid: 7\n\n")
        self.assertEqual([event["_id"] for event in events], [7])

    def test_multiple_data_lines_are_joined(self):
        body = (
            b'id: 7\ndata: {"transaction_id":"tx",\n'
            b'data: "event":{"payload":{"sale_ref":"unused","amount":"1"}}}\n\n'
        )
        events, _ = self.read(body)
        self.assertEqual([event["_id"] for event in events], [7])

    def test_comment_before_backlog_is_ignored(self):
        events, _ = self.read(b": keepalive\n\n" + frame(7))
        self.assertEqual([event["_id"] for event in events], [7])

    def test_current_esmeralda_encoding_still_works(self):
        events, _ = self.read(frame(7))
        self.assertEqual([event["_id"] for event in events], [7])

    def test_legal_compact_frame_cannot_be_skipped_by_later_id(self):
        events, _ = self.read(
            b"id:139\ndata:" + payment_body("tx139") + b"\n\n" + frame(140, payment_body("tx140"))
        )
        self.assertEqual([event["_id"] for event in events], [139, 140])

    def test_response_is_bounded_at_four_mib(self):
        response = Response(b"x" * (G.MAX_RESPONSE_BYTES + 100) + b"\n")
        with patch("urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(ValueError, "exceeded"):
                G.read_events(0, timeout=1)
        self.assertEqual(response.bytes_read, G.MAX_RESPONSE_BYTES + 1)


class TransactionOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.scratch = Path(self.tempdir.name)
        self.old_paths = G.KEYS, G.RUN, G.LEDGER
        G.KEYS = self.scratch
        G.RUN = self.scratch / "run"
        G.LEDGER = self.scratch / "ledger.sqlite3"
        self.db = G.open_ledger()
        public_key = X25519PrivateKey.generate().public_key().public_bytes_raw()
        self.subscriber = E.b64(public_key)
        self.reference = f"CF1.{self.subscriber}.t3.{E.b64(os.urandom(9))}"

    def tearDown(self):
        self.db.close()
        G.KEYS, G.RUN, G.LEDGER = self.old_paths
        self.tempdir.cleanup()

    def event(self, event_id: int = 1, tx_id: str = "tx1") -> dict:
        return {
            "_id": event_id,
            "transaction_id": tx_id,
            "event": {"payload": {
                "sale_ref": self.reference,
                "amount": str(G.PRICE_MICROXTR_PER_TITLE),
            }},
        }

    def test_abort_is_refused_without_a_grant(self):
        with patch.object(G, "read_transaction_outcome", return_value="Abort"):
            verdict = G.credit(self.db, self.event(), 1_800_000_000)
        row = self.db.execute("SELECT verdict, issued FROM payments").fetchone()
        self.assertEqual(verdict, "refused")
        self.assertIn("Abort", row["verdict"])
        self.assertEqual(row["issued"], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)

    def test_unreadable_transaction_is_persisted_pending_then_retried(self):
        unavailable = G.UnresolvedTransaction("HTTP 503")
        with patch.object(G, "read_transaction_outcome", side_effect=unavailable):
            verdict = G.credit(self.db, self.event(), 1_800_000_000)
        row = self.db.execute("SELECT verdict, issued FROM payments").fetchone()
        self.assertEqual((verdict, row["verdict"], row["issued"]), ("unresolved", "unresolved", 0))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        self.assertEqual(G.issue_pending(self.db, None, 0, 1_800_000_000), 0)

        G.set_cursor(self.db, 1)
        self.db.commit()
        with patch.object(G, "read_transaction_outcome", return_value="Commit"):
            self.assertEqual(G.retry_unresolved(self.db, 1_800_000_001), ["credited"])
        row = self.db.execute("SELECT verdict, issued FROM payments").fetchone()
        self.assertEqual((row["verdict"], row["issued"]), ("credited", 0))
        self.assertEqual(G.cursor(self.db), 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 1)

    def test_replaying_resolved_event_changes_nothing(self):
        event = self.event()
        with patch.object(G, "read_transaction_outcome", return_value="Commit") as outcome:
            self.assertEqual(G.credit(self.db, event, 1_800_000_000), "credited")
            before = self.db.total_changes
            self.assertEqual(G.credit(self.db, event, 1_800_000_100), "duplicate")
        self.assertEqual(self.db.total_changes, before)
        outcome.assert_called_once_with("tx1")

    def test_two_pay_calls_in_one_transaction_remain_two_events(self):
        second = self.event(event_id=2, tx_id="tx1")
        with patch.object(G, "read_transaction_outcome", return_value="Commit"):
            self.assertEqual(G.credit(self.db, self.event(), 1_800_000_000), "credited")
            self.assertEqual(G.credit(self.db, second, 1_800_000_000), "credited")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 2)

    def test_transaction_reader_extracts_explicit_outcome(self):
        body = json.dumps({"transaction": {
            "transaction_id": "tx1",
            "summary": {"outcome": "Abort"},
        }}).encode()
        with patch("urllib.request.urlopen", return_value=Response(body)):
            self.assertEqual(G.read_transaction_outcome("tx1"), "Abort")

    def test_transaction_reader_leaves_http_failure_unresolved(self):
        error = urllib.error.HTTPError("url", 503, "unavailable", {}, None)
        try:
            with patch("urllib.request.urlopen", side_effect=error):
                with self.assertRaisesRegex(G.UnresolvedTransaction, "503"):
                    G.read_transaction_outcome("tx1")
        finally:
            error.close()


if __name__ == "__main__":
    unittest.main()


class HouseBudgetTests(unittest.TestCase):
    """The house's cumulative spending ceiling.

    `cover --max` bounds one sweep; `./catflix serve` sweeps forever, so until
    `--budget` existed the only limit on house spending was how long the seller
    was left running. The queue is unsigned and grow-only on purpose, so anyone
    can append fresh valid references indefinitely.
    """

    def setUp(self):
        self.old_paths = G.KEYS, G.RUN, G.LEDGER
        self.tmp = tempfile.TemporaryDirectory()
        self.scratch = Path(self.tmp.name)
        G.KEYS = self.scratch
        G.RUN = self.scratch / "run"
        G.LEDGER = self.scratch / "ledger.sqlite3"
        self.db = G.open_ledger()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        G.KEYS, G.RUN, G.LEDGER = self.old_paths

    def _spent(self):
        return self.db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS t FROM covered WHERE outcome = 'paid'"
        ).fetchone()["t"]

    def _cover(self, reference, amount, outcome="paid"):
        self.db.execute(
            "INSERT OR REPLACE INTO covered (sale_ref, amount, tx_id, outcome, covered_at)"
            " VALUES (?,?,?,?,?)",
            (reference, amount if outcome == "paid" else 0, "tx", outcome, 0),
        )
        self.db.commit()

    def test_spend_is_summed_from_the_ledger_so_a_restart_does_not_reset_it(self):
        self.assertEqual(self._spent(), 0)
        self._cover("CF1.a.t1.x", G.PRICE_MICROXTR_PER_TITLE)
        self._cover("CF1.b.t2.x", G.PRICE_MICROXTR_PER_TITLE)
        self.assertEqual(self._spent(), 2 * G.PRICE_MICROXTR_PER_TITLE)
        # Reopening is what a restarted seller does.
        self.db.close()
        self.db = G.open_ledger()
        self.assertEqual(self._spent(), 2 * G.PRICE_MICROXTR_PER_TITLE)

    def test_a_refused_payment_costs_nothing_against_the_budget(self):
        self._cover("CF1.c.t3.x", G.PRICE_MICROXTR_PER_TITLE, outcome="refused")
        self.assertEqual(self._spent(), 0)

    def test_the_budget_is_reached_by_repetition_not_by_one_large_order(self):
        # The drain this ceiling exists to stop: many small, individually
        # legitimate orders, none of which a per-sweep cap would refuse.
        per_sweep = 2
        sweeps = 0
        while self._spent() + per_sweep * G.PRICE_MICROXTR_PER_TITLE <= G.HOUSE_BUDGET_MICROXTR:
            for n in range(per_sweep):
                self._cover(f"CF1.k{sweeps}_{n}.t1.x", G.PRICE_MICROXTR_PER_TITLE)
            sweeps += 1
            self.assertLess(sweeps, 1000, "budget never became binding")
        self.assertGreater(sweeps, 0)
        self.assertLessEqual(self._spent(), G.HOUSE_BUDGET_MICROXTR)
        # And the next sweep must be refused rather than partially paid.
        self.assertGreater(
            self._spent() + per_sweep * G.PRICE_MICROXTR_PER_TITLE,
            G.HOUSE_BUDGET_MICROXTR,
        )
