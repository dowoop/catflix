#!/usr/bin/env python3
"""Disposable Ootle identities for autonomous agents.

An agent that has to prove a sale end to end needs a funded XTR account. The
obvious way to give it one is to hand it ``OOTLE_KEY_PASSPHRASE``, which
unseals the dev-bench customer key holding ~989 XTR. This module exists so
that never has to happen.

WHAT AN AGENT CAN DO WITHOUT ANY SECRET OF YOURS, measured 2026-09-01:

    toolkit devbench account    mints a key -- a fresh one is written PLAINTEXT
    toolkit devbench faucet     creates AND funds the account (1,000 XTR a call)
    toolkit devbench pay-sale   withdraws from the AGENT's account, agent-signed

Verified end to end: CPS-2026-00532 was charged, paid from a key this module's
scheme owns, settled, and booked as ACC-SINV-2026-00119. The agent's account
paid the fee too -- its balance fell by 5,004,401 uT for a 5,000,000 uT sale --
so the merchant sponsored nothing.

## The three hazards this module exists to close

**1. `OOTLE_DEVBENCH_N` falls back to the SEALED key.** The toolkit reads that
variable and does `.unwrap_or(1)`, and slot 1 is the merchant's real 989-XTR
customer key. An agent that simply forgets to set the variable operates against
it. That is the whole footgun, and it is why identities here are named rather
than numbered by the caller, and why `_slot` can never return a number below
`AGENT_SLOT_BASE`.

**2. A broker that seals is a privilege escalation.** `toolkit submit-request`
decodes whatever `unsigned_cbor` it is handed, attaches the customer signature,
and then seals the result with THIS machine's wallet. The signature check
proves the agent signed those bytes; it does not prove the bytes are a payment.
Automating that path would let an agent choose the instructions and have the
merchant authorise them -- draining the payment component's takings is one of
the things it could choose. So this module refuses to construct that verb at
all: see `_ALLOWED_VERBS`. If a future caller needs it, it needs a stateful
policy broker that retains its own bytes, not a flag here.

**3. A passphrase in the environment is inherited.** `subprocess` passes the
parent's environment by default, so an agent running in a shell where
`OOTLE_KEY_PASSPHRASE` happens to be exported could unseal slot 1 through this
module. `_child_environment` strips it. The agent path is not merely expected
not to use the merchant key -- it is unable to.

## Discipline, and why it is not a balance check

The faucet is a shared public testnet resource and grants 1,000 XTR a call with
no visible rate limit. Looping it is abuse. The obvious guard -- faucet only
when the balance is low -- would need this module to read the indexer. That
used to mean a second copy of a vault walk that only existed in a library, and
two copies of one rule is how they drift; the walk lives here now, in
`ootle_read.resource_balance`, so that objection is gone.

The guard is still not a balance check, for the reason that outlived it: a
balance read can come back UNREADABLE, and a faucet guard that cannot decide
is a guard that either fails open or stops an agent working because a public
indexer was slow. The discipline is kept in state this module already owns --
a cooldown and a lifetime cap per identity, both enforced under a file lock so
concurrent agents cannot race past them -- and that answer is the same whether
or not anything answers.

## WHAT THIS IS NOT — read this before trusting it

**This is a safety rail, not a security boundary.** An adversary executing
code as this Unix user defeats it, and no amount of work inside this file
changes that. Such a process can read `os.environ`, read the key files
directly, run the toolkit itself, or edit this module. A Codex review put it
plainly and it is correct:

    The narrow assumption under which the intended guarantee could hold is:
    the agent has access only to a separately privileged broker [...] and no
    merchant passphrase is visible to any process under the agent's Unix
    identity. That isolation is not implemented here.

So the honest claim is the smaller one, and a second review pass narrowed it
again to exactly this:

    With an intact and mutually consistent registry/key directory, no
    concurrent lifecycle operations on the same identity, cooperative callers
    restricted to the public wrapper, and this exact toolkit implementation,
    the wrapper prevents selecting sealed slot 1 and prevents invoking
    `submit-request`.

Two things it does NOT claim, both corrected after review. The child process
still LOADS the merchant's operational key before it dispatches `devbench` and
changes the default signer -- the payment is signed by the agent, but the
credential is in that process, so "the child cannot reach a merchant key" would
be false. And a real boundary needs a separate Unix principal, which is
deliberately out of scope.

Every entry point is total. Nothing here raises; a refusal is a returned
`Result` whose `ok` is False and whose `reason` says why.
"""

import errno
import fcntl
import json
import os
import re
import subprocess
import tempfile
import time

TOOLKIT_PATHS = (
    os.path.join("ootle", "toolkit", "target", "release", "toolkit"),
    os.path.join("ootle", "toolkit", "target", "debug", "toolkit"),
)

# Slot 1 is the sealed merchant customer key. Slots 2 and 3 are legacy
# plaintext keys that predate this module (created 2026-08-14) and are not
# ours to reuse or retire. Agent identities start well clear of all three, so
# an arithmetic slip cannot land on one.
AGENT_SLOT_BASE = 1000
FORBIDDEN_SLOTS = (1, 2, 3)

# AN UPPER BOUND, AND IT IS LOAD-BEARING. The toolkit parses
# `OOTLE_DEVBENCH_N` as a Rust `u32` and does `.unwrap_or(1)` when the parse
# fails -- so a slot of 4294967296 does not overflow, it silently becomes
# SLOT 1, the sealed merchant key. A lower bound alone does not close the
# fallback; it has to be a range. Found by a Codex review of this file.
MAX_AGENT_SLOT = 65535

# A faucet call is free and grants 1,000 XTR -- about 200 sales at the 5 XTR
# ticket this deployment charges. An identity needing a sixth call is not
# running a demo, it is looping.
FAUCET_COOLDOWN_SECONDS = 3600
FAUCET_LIFETIME_MAX = 5

# A PER-IDENTITY CAP CAPS NOTHING when identities are free to mint. The first
# version of this module had only the per-slug cap, and the loop that defeats
# it is four lines: mint("agent-1"), fund it, mint("agent-2"), fund it. So the
# budget that actually binds is global, it counts grants rather than
# identities, and `retire` deliberately does NOT decrement it -- otherwise
# retiring is the reset. Also found by review.
GLOBAL_FAUCET_MAX = 25

# The verbs an agent identity may ever drive. `submit-request`, `sign-request`
# and every `--compose` handoff are absent DELIBERATELY -- see hazard 2 above.
# A whitelist rather than a blacklist, because the failure of a blacklist is a
# verb nobody thought of.
_ALLOWED_VERBS = ("account", "faucet", "pay-sale")

PASSPHRASE_ENV = "OOTLE_KEY_PASSPHRASE"
SLOT_ENV = "OOTLE_DEVBENCH_N"
# The instant after which the TOOLKIT must not submit. Checked again inside the
# child immediately before `send_transaction`, because everything between this
# module's last check and that call -- connecting, reading the epoch,
# preparing, signing -- is network-capable and can outlive the window on its
# own. See `refuse_if_window_closed` in the toolkit.
DEADLINE_ENV = "OOTLE_PAY_DEADLINE_EPOCH"

TIMEOUT_S = 150.0

# A lease must outlast the child it is protecting. `TIMEOUT_S` is when THIS
# process gives up; a child that was killed can still be finishing, and a
# parent that was itself killed leaves an orphan the OS does not reap for us.
# So the lease is deliberately longer than the timeout. It is still a lease and
# not a proof -- an orphaned child outliving it will not be noticed.
LEASE_SECONDS = TIMEOUT_S + 60

_root = os.path.dirname(os.path.abspath(__file__))
_TX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$")
_ARG_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
# The toolkit reports a watch that ran out as `Timeout { tx_id:
# TransactionId([153, 172, ...]) }` -- a submitted transaction whose OUTCOME is
# unknown, not a transaction that failed.
_TIMEOUT_RE = re.compile(r"Timeout\s*\{\s*tx_id:\s*TransactionId\(\[([0-9,\s]+)\]\)")

_REGISTRY_DIR = os.path.join(os.path.expanduser("~"), ".cryptopos_learning")
_REGISTRY = os.path.join(_REGISTRY_DIR, "agent_wallets.json")
_REGISTRY_LOCK = os.path.join(_REGISTRY_DIR, "agent_wallets.lock")


class Result:
    """One total answer. Callers branch on ``ok`` and print ``reason``."""

    def __init__(self, ok, reason, **fields):
        self.ok = bool(ok)
        self.reason = str(reason)
        self.fields = dict(fields)

    def __getattr__(self, name):
        # `self.fields` here would recurse forever if `fields` were itself
        # absent -- which happens during unpickling and during any partially
        # constructed instance. Reach into __dict__ instead, so a missing
        # attribute raises AttributeError like any other object.
        fields = object.__getattribute__(self, "__dict__").get("fields") or {}
        try:
            return fields[name]
        except KeyError:
            raise AttributeError(name) from None

    def __repr__(self):                                  # pragma: no cover
        return f"Result(ok={self.ok}, reason={self.reason!r}, {self.fields!r})"


def _fail(reason, **fields):
    return Result(False, reason, **fields)


def toolkit_path():
    """The executable toolkit, resolved afresh on every call."""
    try:
        for relative in TOOLKIT_PATHS:
            candidate = os.path.join(_root, relative)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    except Exception:                                    # noqa: BLE001 - total
        return ""
    return ""


def _valid_id(agent_id):
    """A lowercase slug. Names are checkable by eye; numbers are not."""
    try:
        return bool(agent_id) and isinstance(agent_id, str) and bool(_ID_RE.fullmatch(agent_id))
    except Exception:                                    # noqa: BLE001 - total
        return False


def _child_environment(slot, deadline=None):
    """The child's environment: the slot pinned, the passphrase REMOVED.

    Removing it is the half that matters. Pinning `OOTLE_DEVBENCH_N` stops the
    toolkit defaulting to slot 1; stripping the passphrase means that even if
    the pin were wrong, the sealed key still could not be opened. Two
    independent reasons the merchant's key stays shut, because a single guard
    is one mistake from being no guard.
    """
    environment = dict(os.environ)
    environment.pop(PASSPHRASE_ENV, None)
    environment[SLOT_ENV] = str(int(slot))
    # PIN HOME TO THE DIRECTORY THIS MODULE ACCOUNTS FOR. `_REGISTRY_DIR` is
    # resolved once at import; the toolkit resolves its key path from the
    # CHILD's HOME on every run. If HOME changed after import -- or a caller
    # set it -- `retire()` would delete from one directory while `mint` created
    # in another, and the registry would describe neither. Pinning makes the
    # two agree by construction rather than by coincidence.
    environment["HOME"] = os.path.dirname(_REGISTRY_DIR) or environment.get("HOME", "")
    # A stale deadline inherited from the parent would refuse every later
    # payment, so it is set when given and REMOVED when not.
    environment.pop(DEADLINE_ENV, None)
    if deadline:
        try:
            environment[DEADLINE_ENV] = str(int(deadline))
        except Exception:                                # noqa: BLE001 - total
            pass
    return environment


def _load_registry_text(raw):
    """Parse the registry, or ``None`` if it cannot be trusted."""
    try:
        if not raw.strip():
            return {"identities": {}, "next_slot": AGENT_SLOT_BASE,
                    "faucet_grants_total": 0}
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            return None
        loaded.setdefault("identities", {})
        loaded.setdefault("next_slot", AGENT_SLOT_BASE)
        loaded.setdefault("faucet_grants_total", 0)
        loaded.setdefault("payments", {})
        if not isinstance(loaded["identities"], dict):
            return None
        if not isinstance(loaded["payments"], dict):
            return None
        # AND EVERY ENTRY, not just the container. `{"identities": {"broken": 17}}`
        # is valid JSON with a dict at the top, and it reached `list`, which
        # called `.get()` on an int and raised AttributeError out of a module
        # whose docstring promises every entry point is total. Checking the
        # container and calling that "validated" is the guard-narrower-than-its-
        # heading defect again.
        for entry in loaded["identities"].values():
            if not isinstance(entry, dict):
                return None
        for record in loaded["payments"].values():
            if not isinstance(record, dict):
                return None
        try:
            loaded["next_slot"] = max(int(loaded["next_slot"]), AGENT_SLOT_BASE)
            loaded["faucet_grants_total"] = max(int(loaded["faucet_grants_total"]), 0)
        except Exception:                                # noqa: BLE001 - total
            return None
        return loaded
    except Exception:                                    # noqa: BLE001 - total
        # An unreadable registry is not licence to mint into an unknown slot.
        return None


def _store_registry(registry):
    """Replace the registry ATOMICALLY: temp file, fsync, rename, fsync dir.

    Truncate-then-write leaves a window in which the file on disk is neither
    the old registry nor the new one. This module's loader refuses an
    unreadable registry, so that window failed safe -- but "fails safe" and
    "cannot happen" are different promises, and the second one is free here.
    `os.replace` is atomic within a filesystem, and the directory fsync is what
    makes the rename itself durable rather than merely ordered.
    """
    fd, temporary = tempfile.mkstemp(dir=_REGISTRY_DIR, prefix=".agent_wallets-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(registry, indent=2, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, _REGISTRY)
        temporary = ""
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    # THE DIRECTORY FSYNC IS NOT OPTIONAL AND ITS FAILURE IS NOT IGNORABLE.
    # `os.replace` makes the swap atomic; only this makes the swap DURABLE.
    # Swallowing the error meant `pay_sale` could write its attempt record,
    # believe it was on disk, pay, lose power, and come back with no record --
    # and then accept the retry that pays twice. The whole retry guarantee
    # rests on this write surviving, so a failure here must reach the caller.
    directory = os.open(_REGISTRY_DIR, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_registry_bytes():
    """Read the registry, refusing a symlink.

    O_NOFOLLOW is not a defence against the same-user adversary this module
    has already said it cannot stop. It is a defence against the ordinary
    accident -- a stray symlink left by a backup tool or an earlier
    experiment -- writing this module's state onto somebody else's file.
    """
    try:
        fd = os.open(_REGISTRY, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r") as handle:
            return handle.read()
    except Exception:                                    # noqa: BLE001 - total
        return None


class _Registry:
    """The registry, held under an exclusive lock for the whole transaction.

    Codex's review of this design named a non-atomic counter as the way two
    agents get the same slot, and separately named retries duplicating work
    because nothing is idempotent. Both are answered by doing the read, the
    decision and the write inside one lock rather than three calls.
    """

    def __init__(self):
        self.lock = None
        self.data = None
        self.unsafe_directory = False

    def __enter__(self):
        os.makedirs(_REGISTRY_DIR, mode=0o700, exist_ok=True)
        # `makedirs` does not tighten a directory that already exists, and this
        # one predates the module -- it is 0775 today. Group-writable is
        # tolerated (the group is the operator's own); WORLD-writable is not,
        # because then any account on the box can swap the lock or the registry
        # for a symlink. Refusing is the only honest answer: this module cannot
        # fix the permission and must not pretend the lock means something.
        try:
            mode = os.stat(_REGISTRY_DIR).st_mode
            if mode & 0o002:
                self.data = None
                self.unsafe_directory = True
                return self
        except OSError:
            pass
        self.lock = open(_REGISTRY_LOCK, "a+")
        try:
            os.chmod(_REGISTRY_LOCK, 0o600)
        except OSError:
            pass
        fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX)
        # `lexists`, not `exists`: a DANGLING symlink is invisible to `exists`,
        # so opening "w" here would follow it and create the target. `lexists`
        # sees the link itself, the creation is skipped, and the O_NOFOLLOW
        # read below then refuses it like any other symlink.
        if not os.path.lexists(_REGISTRY):
            fd = os.open(_REGISTRY,
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        raw = _read_registry_bytes()
        if raw is None:
            self.data = None
            return self
        self.data = _load_registry_text(raw)
        return self

    def save(self):
        _store_registry(self.data)

    def __exit__(self, *_):
        try:
            if self.lock is not None:
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_UN)
                self.lock.close()
        except Exception:                                # noqa: BLE001 - total
            pass
        return False


def _mark_in_flight(identity):
    """Record that ONE operation has started, and return its own token.

    A single `in_flight_at` timestamp was wrong under concurrency: two
    operations wrote one field and whichever finished first cleared it, so
    `retire` was allowed while the other child was still alive -- and the
    toolkit RECREATES a missing key rather than failing, so the deleted key
    came back, funded and unregistered. A token per operation means an
    operation can only ever clear its own.
    """
    token = "%d-%d" % (os.getpid(), time.time_ns())
    identity.setdefault("in_flight", {})[token] = int(time.time())
    return token


def _clear_in_flight(identity, token):
    flights = identity.get("in_flight")
    if isinstance(flights, dict):
        flights.pop(token, None)
        if not flights:
            identity.pop("in_flight", None)


def _live_flights(identity):
    """Operations started recently enough that a child may still be alive."""
    flights = identity.get("in_flight")
    if not isinstance(flights, dict):
        return []
    now = int(time.time())
    live = []
    for token, started in flights.items():
        try:
            if now - int(started) < LEASE_SECONDS:
                live.append(token)
        except Exception:                                # noqa: BLE001 - total
            live.append(token)
    return live


def _entry_slot(entry):
    try:
        return int(entry["slot"])
    except Exception:                                    # noqa: BLE001 - total
        return None


def _slot(registry, agent_id, create):
    """The slot for this identity, assigning one on first sight.

    Never returns a forbidden slot, and never returns a number below
    `AGENT_SLOT_BASE`. A caller cannot choose its own slot -- that is the
    point. Returns ``(slot, error)``.
    """
    entry = registry["identities"].get(agent_id)
    if entry is not None:
        try:
            slot = int(entry["slot"])
        except Exception:                                # noqa: BLE001 - total
            return 0, "this identity's registry entry has no usable slot"
        # Allocation avoids collisions; that says nothing about a registry
        # that ALREADY holds two entries on one slot -- from a hand edit, a
        # merge, or a restored backup. Two identities sharing a slot share a
        # key, and every guarantee here is about an identity owning its own.
        sharers = [name for name, other in registry["identities"].items()
                   if name != agent_id and _entry_slot(other) == slot]
        if sharers:
            return 0, (f"slot {slot} is claimed by {agent_id!r} and also by "
                       f"{', '.join(sorted(sharers))} -- two identities cannot share "
                       "a key. Retire all but one before using it.")
        if slot in FORBIDDEN_SLOTS or not (AGENT_SLOT_BASE <= slot <= MAX_AGENT_SLOT):
            return 0, (f"identity {agent_id!r} names slot {slot}, which is outside the "
                       f"agent range {AGENT_SLOT_BASE}-{MAX_AGENT_SLOT}. Refusing rather "
                       "than operating on a key that is not an agent's -- a slot above "
                       "u32 does not overflow in the toolkit, it becomes slot 1.")
        return slot, None
    if not create:
        return 0, f"no agent identity named {agent_id!r} has been minted"

    taken = set()
    for other in registry["identities"].values():
        found = _entry_slot(other)
        if found is not None:
            taken.add(found)
    # AND A SLOT WHOSE KEY FILE ALREADY EXISTS IS NOT FREE, whatever the
    # registry says. Delete `agent_wallets.json`, or restore an older copy,
    # and `next_slot` returns to 1000 -- but the toolkit's `devbench account`
    # OPENS an existing key rather than creating one, so the next identity
    # minted would silently inherit the previous agent's funded account. The
    # registry is not the only state; the key directory is state too.
    # Searching from the base rather than from `next_slot` also means retiring
    # an identity genuinely frees its slot, which is what the exhaustion
    # message tells the operator to do.
    slot = AGENT_SLOT_BASE
    # `next_slot` alone is not enough: a registry restored from a backup, or
    # hand-edited, can carry a counter behind the entries it already holds.
    # Handing out a slot that is already taken hands out somebody else's key.
    while (slot in FORBIDDEN_SLOTS or slot in taken
           or os.path.lexists(_key_path(slot))):
        slot += 1
    if slot > MAX_AGENT_SLOT:
        return 0, (f"no agent slot is free below {MAX_AGENT_SLOT}; retire some "
                   "identities before minting more")
    registry["next_slot"] = slot + 1
    registry["identities"][agent_id] = {
        "slot": slot,
        "minted_at": int(time.time()),
        "faucet_calls": 0,
        "last_faucet_at": 0,
        "sales_paid": 0,
    }
    return slot, None


# The toolkit parses the amount as a Rust `u64`. A Python int is unbounded, so
# a value above this is accepted here and refused there -- after the attempt
# record has been written, which then blocks the corrected retry.
MAX_MICROTARI = 2 ** 64 - 1


def _component_ok(value):
    """A component address as the toolkit will actually parse it.

    `_safe_argument` only asks whether an argument is harmless to pass. That
    let `"not-a-component"` through to the Rust `ComponentAddress` parser,
    which refuses it -- after the attempt record was written, poisoning the
    sale reference for the corrected call. A wrapper that validates less than
    the thing it wraps turns a caller's typo into a blocked sale.
    """
    try:
        text = str(value).strip()
    except Exception:                                    # noqa: BLE001 - total
        return False
    body = text[len("component_"):] if text.startswith("component_") else text
    return len(body) == 64 and all(c in "0123456789abcdefABCDEF" for c in body)


def _whole(value):
    """A positive whole number of microTari within u64, or ``None``.

    Never truncates.

    Three shapes reach here and each needs its own answer, which the first
    version of this got wrong in both directions. `int()` TRUNCATES, so
    5000000.9 was silently SENT as 5000000 under a message that said "whole
    number". The fix compared `int(value) != value` -- which then refused the
    CLI's own perfectly good "5000000", because an int never equals a str.
    A validator that is wrong in either direction is not a validator.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _bounded(value)
    if isinstance(value, float):
        return _bounded(int(value)) if value.is_integer() else None
    if isinstance(value, str):
        text = value.strip()
        return _bounded(int(text)) if text.isdigit() else None
    return None


def _bounded(number):
    return number if 0 <= number <= MAX_MICROTARI else None


def _safe_argument(value):
    """A toolkit argument that cannot be mistaken for an option or a path.

    A leading `-` would be read as a flag. Everything this module passes is an
    address, an integer, or a sale reference, and none of those contain a
    character outside this set.
    """
    try:
        text = str(value)
    except Exception:                                    # noqa: BLE001 - total
        return ""
    if not text or text.startswith("-") or len(text) > 256:
        return ""
    return text if _ARG_RE.fullmatch(text) else ""


def _argv_for(verb, arguments):
    """Build the toolkit's argv HERE, from a fixed table.

    THE CALLER DOES NOT SUPPLY ARGV, and that is the whole point of this
    function. The first version of this module took an `argv_tail` from its
    callers and checked `argv_tail[1]` against a whitelist -- but the toolkit
    dispatches on `argv_tail[0]`, so `["submit-request", "account", ...]`
    passed the check and RAN `submit-request`. Reproduced: the toolkit
    executed it and failed only because the named file did not exist.

    A whitelist that inspects data somebody else shaped is a whitelist waiting
    to be walked around. Constructing the command from a closed table removes
    the argument the attacker was supplying.
    """
    if verb == "account":
        return ["devbench", "account"]
    if verb == "faucet":
        return ["devbench", "faucet"]
    if verb == "pay-sale":
        component, amount, sale_ref = arguments
        component = _safe_argument(component)
        sale_ref = _safe_argument(sale_ref)
        if not component or not sale_ref:
            return []
        return ["devbench", "pay-sale", component, str(int(amount)), sale_ref]
    return []


def _key_path(slot):
    """Where the toolkit keeps this slot's key, by the toolkit's own rule."""
    return os.path.join(_REGISTRY_DIR,
                        f"ootle_devbench_customer_key_{int(slot)}.json")


def _run(slot, verb, arguments=(), deadline=None):
    """Run one toolkit verb from the closed table. ``(returncode, output)``."""
    # CODE 2 MEANS "NO CHILD EVER STARTED", and the distinction is load-bearing:
    # `pay_sale` clears its attempt record on a 2 and keeps it on a 1. Without
    # it, a missing toolkit or a bad argument permanently blocked the sale
    # reference for the corrected call, under a message about paying twice.
    binary = toolkit_path()
    if not binary:
        return 2, "the Ootle toolkit is not built"
    if verb not in _ALLOWED_VERBS:
        return 2, f"refused: {verb!r} is not an allowed agent verb"
    try:
        slot = int(slot)
    except Exception:                                    # noqa: BLE001 - total
        return 2, "refused: the slot is not a number"
    if slot in FORBIDDEN_SLOTS or not (AGENT_SLOT_BASE <= slot <= MAX_AGENT_SLOT):
        # The last gate before a subprocess. Every caller checks this too; a
        # guard that only exists at the caller is a guard the next caller
        # forgets.
        return 2, f"refused: slot {slot} is not an agent slot"
    try:
        argv = _argv_for(verb, arguments)
    except Exception:                                    # noqa: BLE001 - total
        # `_argv_for` unpacks its arguments. A caller passing the wrong arity
        # raised ValueError straight out of this function, which made the
        # module's "every entry point is total" claim false. Found by review.
        argv = []
    if not argv:
        return 2, f"refused: {verb!r} was given arguments this module will not pass"
    try:
        done = subprocess.run(
            [binary] + argv, cwd=_root,
            capture_output=True, text=True, timeout=TIMEOUT_S,
            stdin=subprocess.DEVNULL, env=_child_environment(slot, deadline),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 1, "timeout"
    except Exception as error:                           # noqa: BLE001 - total
        # `Popen`/exec failed: the child never ran, so this is a 2 as well.
        return 2, f"could not run the toolkit ({type(error).__name__})"
    # A LAUNCHED CHILD NEVER RETURNS 2 FROM HERE. Code 2 is this module's
    # private signal for "no child ever started", and the toolkit is free to
    # exit 2 for reasons of its own. Passing that through would make `pay_sale`
    # ERASE the attempt record for a payment the child may well have submitted
    # -- which is precisely the double-pay this module exists to prevent. So
    # every outcome of a child that did start collapses to 0 or 1.
    return (0 if done.returncode == 0 else 1), (done.stdout or "") + (done.stderr or "")


def _submitted_but_unwatched(output):
    """The transaction id of a payment whose WATCH timed out, or "".

    A TIMEOUT IS NOT A FAILURE, and calling it one costs real money. Measured
    here on 2026-09-01: `pay_sale` returned "the payment did not commit" for a
    watch that ran out, the caller did the natural thing and ran it again, and
    sale CPS-2026-00534 settled having been credited 10,000,000 uT against a
    5,000,000 uT invoice. Both payments had landed. The toolkit had told us so
    -- its error carries the tx_id of a transaction it had already submitted --
    and the module threw that away and reported a flat refusal.

    So a timeout returns INDETERMINATE, carrying the id, and says not to retry.
    """
    match = _TIMEOUT_RE.search(str(output or ""))
    if not match:
        return ""
    try:
        octets = [int(part) for part in match.group(1).split(",") if part.strip()]
        if len(octets) != 32 or any(not 0 <= b <= 255 for b in octets):
            return ""
        return bytes(octets).hex()
    except Exception:                                    # noqa: BLE001 - total
        return ""


def _field(output, name):
    for line in str(output or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == name:
            return fields[1]
    return ""


def mint(agent_id):
    """Create (or return) this agent's own Ootle identity. Offline."""
    if not _valid_id(agent_id):
        return _fail("an agent id must be a lowercase slug, 2-40 characters, "
                     "like 'claude-e2e' -- names are checkable by eye")
    if not toolkit_path():
        return _fail("the Ootle toolkit is not built; build ootle/toolkit first")
    try:
        # THE RESERVATION IS PERSISTED BEFORE THE KEY IS CREATED, and the order
        # is the point. The toolkit's `devbench account` CREATES a key file as a
        # side effect of being asked for an address. If the reservation were
        # saved afterwards, a crash or a timeout between the two would leave a
        # key on disk at slot N with `next_slot` still pointing at N -- so the
        # next identity minted would be handed somebody else's existing key.
        # Losing a slot to a failed mint is cheap; sharing one is not.
        with _Registry() as registry:
            if registry.data is None:
                return _fail("the agent registry could not be read; refusing to mint "
                             "into a slot this module cannot account for")
            existing = registry.data["identities"].get(agent_id)
            slot, error = _slot(registry.data, agent_id, create=True)
            if error:
                return _fail(error)
            already_named = bool(existing and existing.get("account"))
            registry.save()

        code, output = _run(slot, "account")
        if code != 0:
            return _fail(f"the toolkit could not mint slot {slot}; the slot stays "
                         f"reserved so nothing else is handed this key", slot=slot)
        address = _field(output, "address")
        account = _field(output, "account")
        if not address or not account:
            return _fail("the toolkit did not name an address and account", slot=slot)

        with _Registry() as registry:
            if registry.data is None:
                return _fail("the registry became unreadable while minting")
            entry = registry.data["identities"].get(agent_id)
            if entry is None:
                return _fail("the identity vanished from the registry while minting")
            # A MINT MUST NOT SILENTLY REPOINT AN IDENTITY. If this slug already
            # named an account and the toolkit now names a different one, the key
            # file changed underneath us -- say so rather than overwrite the
            # record and let a caller believe it is paying from what it minted.
            if already_named and existing.get("account") != account:
                return _fail(
                    f"identity {agent_id!r} already named account "
                    f"{str(existing.get('account'))[:24]}... but slot {slot} now holds "
                    f"{account[:24]}... -- refusing to repoint it", slot=slot)
            entry.update({"address": address, "account": account})
            registry.save()
        return Result(True, f"agent {agent_id!r} holds its own key in slot {slot}",
                      slot=slot, address=address, account=account, agent_id=agent_id)
    except Exception as error:                           # noqa: BLE001 - total
        return _fail(f"the identity could not be minted ({type(error).__name__})")


def fund(agent_id):
    """Take one faucet grant, under a cooldown and a lifetime cap."""
    if not _valid_id(agent_id):
        return _fail("an agent id must be a lowercase slug")
    try:
        with _Registry() as registry:
            if registry.data is None:
                return _fail("the agent registry could not be read; refusing to faucet")
            slot, error = _slot(registry.data, agent_id, create=False)
            if error:
                return _fail(error)
            entry = registry.data["identities"][agent_id]
            calls = int(entry.get("faucet_calls", 0))
            last = int(entry.get("last_faucet_at", 0))
            now = int(time.time())
            spent = int(registry.data.get("faucet_grants_total", 0))
            # THE BUDGET THAT ACTUALLY BINDS. The per-identity cap below is
            # advisory once minting is free: `for i in range(10000): mint(f"a-{i}");
            # fund(f"a-{i}")` takes ten thousand first grants and never trips it.
            # This one counts grants across every identity that has ever existed
            # on this workstation and `retire` does not decrement it, so
            # retiring is not a reset either.
            if spent >= GLOBAL_FAUCET_MAX:
                return _fail(
                    f"this workstation has taken {spent} faucet grants, the global "
                    f"budget of {GLOBAL_FAUCET_MAX}. The faucet is a shared testnet "
                    f"resource; a run needing more is looping. Raise "
                    f"GLOBAL_FAUCET_MAX deliberately if this is genuinely wanted.")
            if calls >= FAUCET_LIFETIME_MAX:
                return _fail(
                    f"identity {agent_id!r} has taken {calls} faucet grants, the "
                    f"lifetime cap. The faucet is a shared testnet resource and "
                    f"1,000 XTR a grant is ~200 sales; an identity needing more is "
                    f"looping. Retire it and mint another if this is deliberate.")
            waited = now - last
            if last and waited < FAUCET_COOLDOWN_SECONDS:
                return _fail(
                    f"identity {agent_id!r} last took a grant {waited}s ago; the "
                    f"cooldown is {FAUCET_COOLDOWN_SECONDS}s.")
            # The counter moves BEFORE the call, so a crash or a timeout costs an
            # attempt rather than granting a free retry. An idempotency key would
            # be better and the toolkit offers none.
            entry["faucet_calls"] = calls + 1
            entry["last_faucet_at"] = now
            registry.data["faucet_grants_total"] = spent + 1
            token = _mark_in_flight(entry)
            registry.save()

        # THE LOCK IS RELEASED BEFORE THE NETWORK CALL, deliberately. A faucet
        # call is bounded by TIMEOUT_S (150 s); holding an exclusive lock
        # across it would make one slow faucet block every other agent's mint,
        # payment and listing for the same 150 s. The decision has already been
        # committed to disk above, so a concurrent caller reads the incremented
        # counter and is refused correctly whether or not this call lands.
        code, output = _run(slot, "faucet")
        with _Registry() as registry:
            if registry.data is not None:
                identity = registry.data["identities"].get(agent_id)
                if identity is not None:
                    _clear_in_flight(identity, token)
                    registry.save()
        if code != 0 or _field(output, "faucet") != "Commit":
            return _fail("the faucet did not commit", attempt=calls + 1)
        return Result(True, f"agent {agent_id!r} funded itself (grant {calls + 1} "
                            f"of {FAUCET_LIFETIME_MAX}; {spent + 1} of "
                            f"{GLOBAL_FAUCET_MAX} workstation-wide)",
                      slot=slot, attempt=calls + 1, global_spent=spent + 1)
    except Exception as error:                           # noqa: BLE001 - total
        return _fail(f"the identity could not be funded ({type(error).__name__})")


def pay_sale(agent_id, component, microtari, sale_ref, force=False, deadline=None):
    """Pay a cryptopos sale through the payment component, naming the sale.

    This is the per-sale binding: the money itself says which sale it settles,
    so two sales open at once cannot be confused. The agent signs and the
    agent's account pays the fee.

    ## Why this refuses a second payment for the same sale

    THE MODULE CANNOT TELL A FAILED PAYMENT FROM AN UNREPORTED ONE, and no
    amount of output parsing fixes that. The toolkit obtains its transaction id
    at submission but does not print it until the watch succeeds, and this
    module kills the child at `TIMEOUT_S`. So a payment that was submitted and
    landed can reach here as a bare "timeout" with nothing to parse.

    That is not hypothetical. On 2026-09-01 a watch timed out, the outcome was
    reported as "the payment did not commit", the natural retry was made, and
    sale CPS-2026-00534 settled having been credited 10,000,000 uT against a
    5,000,000 uT invoice. Both had landed.

    So retry-safety is not built on reading the toolkit. The ATTEMPT is written
    to the registry before the child starts, keyed by `sale_ref`, and a second
    call for that reference is refused. Absence of proof of success is never
    treated as proof of failure: anything but a printed `pay Commit` with a
    usable transaction id comes back INDETERMINATE.

    `force=True` exists for the operator who has checked the terminal and knows
    the first attempt did not land. It is deliberately not a retry default.
    """
    if not _valid_id(agent_id):
        return _fail("an agent id must be a lowercase slug")
    amount = _whole(microtari)
    if amount is None or amount <= 0:
        return _fail(f"a payment must be a positive whole number of microTari; "
                     f"{microtari!r} is not one")
    if not component or not isinstance(component, str):
        return _fail("a payment needs the payment component's address")
    if not sale_ref or not isinstance(sale_ref, str):
        return _fail("a payment must name the sale it is for")
    # VALIDATE BEFORE RECORDING. The attempt record exists to refuse a retry
    # after a child may have submitted; a call refused here never reached a
    # child at all, so recording it would block a legitimate corrected retry
    # and would report a sale as "already attempted" that was never sent.
    if not _component_ok(component):
        return _fail(f"{component!r} is not a component address: 64 hex characters, "
                     "optionally prefixed 'component_'. Validated HERE because the "
                     "toolkit would refuse it after the attempt was recorded.")
    if not _safe_argument(sale_ref):
        return _fail("a sale reference must be letters, digits, and _ . : - only, "
                     "and must not start with '-'")
    if not toolkit_path():
        return _fail("the Ootle toolkit is not built; build ootle/toolkit first")
    try:
        with _Registry() as registry:
            if registry.data is None:
                return _fail("the agent registry could not be read; refusing to pay")
            slot, error = _slot(registry.data, agent_id, create=False)
            if error:
                return _fail(error)
            attempts = registry.data.setdefault("payments", {})
            previous = attempts.get(sale_ref)
            if previous is not None and not force:
                return _fail(
                    f"sale {sale_ref} has already been paid or attempted by "
                    f"{previous.get('agent_id')!r} "
                    f"({previous.get('state')}, tx {previous.get('tx_id') or 'unknown'}). "
                    f"Refusing to pay it twice. Ask the terminal whether it settled; "
                    f"pass force=True only if you have checked and it did not.",
                    sale_ref=sale_ref, previous=previous)
            # THE ATTEMPT IS ON DISK BEFORE THE CHILD STARTS. A crash, a kill,
            # or a lost answer therefore still leaves a record that refuses the
            # retry -- which is the whole point, because those are exactly the
            # cases where the payment may have landed unseen.
            attempts[sale_ref] = {"agent_id": agent_id, "slot": slot,
                                  "amount": amount, "at": int(time.time()),
                                  "state": "submitted-unknown", "tx_id": ""}
            token = _mark_in_flight(registry.data["identities"][agent_id])
            registry.save()

        code, output = _run(slot, "pay-sale", (component, amount, sale_ref),
                            deadline=deadline)
        if code == 2:
            # Nothing was ever launched, so this sale was never paid and must
            # not stay blocked. Forget the attempt and say plainly it did not go.
            with _Registry() as registry:
                if registry.data is not None:
                    registry.data.setdefault("payments", {}).pop(sale_ref, None)
                    identity = registry.data["identities"].get(agent_id)
                    if identity is not None:
                        _clear_in_flight(identity, token)
                    registry.save()
            return _fail(f"the payment was not attempted: {output.strip()}",
                         amount=amount, slot=slot, sale_ref=sale_ref,
                         indeterminate=False)
        tx = _field(output, "tx")
        committed = (code == 0 and _field(output, "pay") == "Commit"
                     and bool(_TX_RE.fullmatch(tx or "")))
        unwatched = _submitted_but_unwatched(output)

        with _Registry() as registry:
            if registry.data is not None:
                record = registry.data.setdefault("payments", {}).get(sale_ref)
                if record is not None:
                    record["state"] = "committed" if committed else "submitted-unknown"
                    record["tx_id"] = tx if committed else unwatched
                identity = registry.data["identities"].get(agent_id)
                if identity is not None:
                    _clear_in_flight(identity, token)
                    if committed:
                        identity["sales_paid"] = int(identity.get("sales_paid", 0)) + 1
                registry.save()

        if committed:
            return Result(True, f"agent {agent_id!r} paid {amount} uT for sale {sale_ref}",
                          tx_id=tx, amount=amount, slot=slot, sale_ref=sale_ref)
        # EVERY non-commit is INDETERMINATE. Not "failed" -- the child may have
        # submitted and been killed before it could say so.
        named = f" as {unwatched}" if unwatched else ""
        return _fail(
            f"the payment for sale {sale_ref} was NOT confirmed{named}, and this "
            f"module cannot say whether it landed -- the toolkit prints its "
            f"transaction id only after the watch succeeds. DO NOT RETRY: ask the "
            f"terminal whether {sale_ref} settled. The attempt is recorded, so a "
            f"second call for this sale is refused.",
            amount=amount, slot=slot, sale_ref=sale_ref,
            tx_id=unwatched, indeterminate=True)
    except Exception as error:                           # noqa: BLE001 - total
        return _fail(f"the payment could not be attempted ({type(error).__name__})",
                     indeterminate=True)


def retire(agent_id):
    """Delete this identity's key and forget it. Any balance is abandoned.

    Abandoning testnet dust is correct: the alternative is a sweep path, and a
    sweep path needs a destination, which reintroduces a standing account for
    an identity whose whole value is that it is disposable.
    """
    if not _valid_id(agent_id):
        return _fail("an agent id must be a lowercase slug")
    try:
        with _Registry() as registry:
            if registry.data is None:
                return _fail("the agent registry could not be read; refusing to retire")
            slot, error = _slot(registry.data, agent_id, create=False)
            if error:
                return _fail(error)
            busy = _live_flights(registry.data["identities"][agent_id])
            if busy:
                return _fail(
                    f"identity {agent_id!r} has {len(busy)} operation(s) in flight. "
                    f"Retiring now would delete a "
                    f"key the toolkit is still using, and the toolkit RECREATES a "
                    f"missing key rather than failing -- so the 'deleted' key would "
                    f"reappear, funded and unregistered. Wait for it to finish.",
                    slot=slot)
            # FORGET IT FIRST, DELETE SECOND. `pay_sale` releases the lock
            # before it launches the toolkit, so a retirement racing a payment
            # is possible either way -- but this order makes the failure safe.
            # Dropping the entry first means a concurrent call refuses with
            # "no such identity"; deleting the key first would leave the entry
            # pointing at a slot whose next use silently CREATES a new key and
            # calls it the same identity.
            registry.data["identities"].pop(agent_id, None)
            registry.save()
            # `slot` is an int inside the agent range, checked by `_slot`, so
            # this name cannot traverse. `unlink` removes a symlink itself
            # rather than its target.
            path = os.path.join(_REGISTRY_DIR,
                                f"ootle_devbench_customer_key_{int(slot)}.json")
            removed = False
            try:
                os.unlink(path)
                removed = True
            except OSError as error:
                if error.errno != errno.ENOENT:
                    return _fail(f"the identity was forgotten but its key file could "
                                 f"not be removed ({error.errno}); delete {path} by hand",
                                 slot=slot)
        return Result(True, f"agent {agent_id!r} retired"
                            f"{' and its key deleted' if removed else ' (no key file found)'}",
                      slot=slot, key_removed=removed)
    except Exception as error:                           # noqa: BLE001 - total
        return _fail(f"the identity could not be retired ({type(error).__name__})")


def identities():
    """Every agent identity this workstation has minted, or ``None``.

    ``None`` means the registry could not be READ -- corrupt, a symlink, or a
    world-writable directory. It is not the same answer as "none minted", and
    returning `{}` for both is how `list` came to print "no agent identities"
    and exit 0 over an unreadable registry: a true condition under a false
    sentence, and the reason this returns a third value instead of two.
    """
    try:
        with _Registry() as registry:
            if registry.data is None:
                return None
            return dict(registry.data["identities"])
    except Exception:                                    # noqa: BLE001 - total
        return None


def _main(argv):
    if len(argv) < 2:
        print(__doc__.splitlines()[0])
        print("\n  agent_wallet.py mint <id>\n  agent_wallet.py fund <id>"
              "\n  agent_wallet.py pay <id> <component> <microTari> <sale-ref>"
              "\n  agent_wallet.py retire <id>\n  agent_wallet.py list")
        return 2
    verb = argv[1]
    if verb == "list":
        rows = identities()
        if rows is None:
            print("REFUSED  the agent registry could not be read -- it may be "
                  "corrupt, a symlink, or in a world-writable directory.")
            print("         This is NOT the same as having no identities.")
            return 1
        if not rows:
            print("no agent identities minted on this workstation")
            return 0
        for name in sorted(rows):
            row = rows[name]
            print(f"{name:24} slot={row.get('slot')} faucet={row.get('faucet_calls')}"
                  f"/{FAUCET_LIFETIME_MAX} sales={row.get('sales_paid')}")
            print(f"{'':24} {str(row.get('account'))[:60]}")
        return 0
    if verb in ("mint", "fund", "retire") and len(argv) >= 3:
        result = {"mint": mint, "fund": fund, "retire": retire}[verb](argv[2])
    elif verb == "pay" and len(argv) >= 6:
        result = pay_sale(argv[2], argv[3], argv[4], argv[5])
    else:
        print(f"unusable arguments for {verb!r}")
        return 2
    print(("OK  " if result.ok else "REFUSED  ") + result.reason)
    for key in sorted(result.fields):
        print(f"    {key:10} {result.fields[key]}")
    return 0 if result.ok else 1


if __name__ == "__main__":                               # pragma: no cover
    import sys
    raise SystemExit(_main(sys.argv))
