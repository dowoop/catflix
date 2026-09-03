"""Sealing a content-key bundle to one subscriber, and signing that it was sold.

This is the only place the wire format is defined. The Freenet contract
verifies what this produces and the browser opens it, so a change here is a
change to two other programs; `signing_message` and `seal` are written to be
read beside `contract/src/lib.rs` and `site/app.js`.

## Why this is hand-rolled, and what that obliges

The counter-argument this design was put through said plainly: do not
hand-roll X25519+AES-GCM, use HPKE. It is right that HPKE is the correct
answer, and it is not available on both sides -- WebCrypto has no HPKE, and a
subscriber's browser is one of the two ends. Shipping a JS HPKE library into a
Freenet web container to avoid writing forty lines is a trade, not a saving.

So this implements DHKEM(X25519, HKDF-SHA256) the way RFC 9180 specifies the
parts that matter, and the two failure modes it names are REFUSALS below
rather than remarks:

  1. an all-zero X25519 shared secret means the recipient key was a low-order
     point, and the "shared" secret is then a constant every reader can
     compute. Sealing to it would publish the bundle while looking encrypted.
  2. the KDF context binds BOTH public keys. Without it a sealed bundle can be
     re-labelled as being for somebody else -- the signature would catch that
     here, but a construction that relies on a signature to be confidential is
     one refactor away from not being confidential.

AES-GCM nonce reuse is the third. Every nonce in this module is 12 fresh
random bytes from `os.urandom`, never a counter, and `catalog/build.py` proves
its own nonces are distinct rather than assuming a random draw was.
"""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass, asdict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Must equal SIGNING_DOMAIN in contract/src/lib.rs. A mismatch is not a subtle
# bug: every signature verifies false and no subscriber can ever be issued.
SIGNING_DOMAIN = b"catflix-entitlement-v1"

# Separate domain for the KDF, so a signature and a key derivation can never
# be made to consume the same bytes.
ENVELOPE_DOMAIN = b"catflix-envelope-v1"

# RFC 5869 says an absent salt is HashLen zero bytes. Written out rather than
# passed as None, because the browser side must supply the same value
# explicitly and "whatever the default is" does not survive being ported.
HKDF_SALT = b"\x00" * 32

NONCE_LEN = 12
KEY_LEN = 32


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Entitlement:
    """Exactly the JSON object the contract stores. Field names are wire."""

    sub: str
    eph: str
    nonce: str
    sealed: str
    issued_at: int
    expires_at: int
    seq: int
    sig: str

    def as_json(self) -> dict:
        return asdict(self)


def signing_message(
    sub: bytes, eph: bytes, nonce: bytes, sealed: bytes,
    issued_at: int, expires_at: int, seq: int,
) -> bytes:
    """The bytes an Ed25519 signature commits to.

    Byte-for-byte `Entitlement::signing_bytes` in the contract. The only
    variable-length field carries a 4-byte big-endian length in front of it,
    so no two different entitlements can share one valid signature by being
    split differently.
    """
    if len(sub) != 32 or len(eph) != 32:
        raise ValueError("public keys must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    if not sealed or len(sealed) > 8 * 1024:
        raise ValueError("sealed bundle is empty or above the contract's 8 KiB bound")
    return (
        SIGNING_DOMAIN
        + sub
        + eph
        + nonce
        + struct.pack(">I", len(sealed))
        + sealed
        + struct.pack(">Q", issued_at)
        + struct.pack(">Q", expires_at)
        + struct.pack(">Q", seq)
    )


def seal(plaintext: bytes, subscriber_pub: bytes) -> tuple[bytes, bytes, bytes]:
    """Seal `plaintext` to a subscriber's X25519 public key.

    Returns (ephemeral_public, nonce, ciphertext).
    """
    if len(subscriber_pub) != 32:
        raise ValueError("a subscriber key must be 32 bytes")

    recipient = X25519PublicKey.from_public_bytes(subscriber_pub)
    ephemeral = X25519PrivateKey.generate()
    eph_pub = ephemeral.public_key().public_bytes_raw()

    shared = ephemeral.exchange(recipient)
    # THE REFUSAL RFC 9180 REQUIRES. A low-order recipient key drives this to
    # all zeros, and every reader on the network can derive the same "secret".
    # `cryptography` raises on some of these already; this does not depend on
    # which ones, because a check that only fires when the library missed one
    # is the check that matters.
    if shared == b"\x00" * 32:
        raise ValueError(
            "refusing to seal: the recipient key produced an all-zero shared secret, "
            "which every reader can compute. This is a low-order point, not a subscriber."
        )

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=HKDF_SALT,
        info=ENVELOPE_DOMAIN + eph_pub + subscriber_pub,
    ).derive(shared)

    nonce = os.urandom(NONCE_LEN)
    aad = ENVELOPE_DOMAIN + subscriber_pub + eph_pub
    return eph_pub, nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(
    ciphertext: bytes, nonce: bytes, eph_pub: bytes, subscriber_priv: X25519PrivateKey
) -> bytes:
    """The subscriber's side. Here so the round trip is testable without a browser."""
    shared = subscriber_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    if shared == b"\x00" * 32:
        raise ValueError("all-zero shared secret on open")
    sub_pub = subscriber_priv.public_key().public_bytes_raw()
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=HKDF_SALT,
        info=ENVELOPE_DOMAIN + eph_pub + sub_pub,
    ).derive(shared)
    aad = ENVELOPE_DOMAIN + sub_pub + eph_pub
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def issue(
    bundle: bytes,
    subscriber_pub: bytes,
    issued_at: int,
    expires_at: int,
    signing_key: Ed25519PrivateKey,
    seq: int = 1,
) -> Entitlement:
    """Seal a bundle of grants to a subscriber and sign that they were sold.

    `seq` is the join key the contract orders on, so it must rise on every
    issuance to one subscriber. Every issuance carries their WHOLE set of
    grants, which is what makes "newest wins" a superset rather than a
    replacement -- buying a second portrait must not drop the first.
    """
    if expires_at <= issued_at:
        raise ValueError("an entitlement that expires before it is issued is not a sale")
    if seq < 1:
        raise ValueError("an issuance sequence starts at 1")
    eph, nonce, sealed = seal(bundle, subscriber_pub)
    message = signing_message(subscriber_pub, eph, nonce, sealed, issued_at, expires_at, seq)
    return Entitlement(
        sub=b64(subscriber_pub),
        eph=b64(eph),
        nonce=b64(nonce),
        sealed=b64(sealed),
        issued_at=issued_at,
        expires_at=expires_at,
        seq=seq,
        sig=b64(signing_key.sign(message)),
    )


def verify(entitlement: Entitlement, gatekeeper_pub: Ed25519PublicKey) -> None:
    """Raises if the contract would refuse this. Used by the tests, not the issuer."""
    message = signing_message(
        unb64(entitlement.sub),
        unb64(entitlement.eph),
        unb64(entitlement.nonce),
        unb64(entitlement.sealed),
        entitlement.issued_at,
        entitlement.expires_at,
        entitlement.seq,
    )
    gatekeeper_pub.verify(unb64(entitlement.sig), message)


def register(entitlements) -> dict:
    """The contract's state object: version, and entries sorted by subscriber.

    Sorting is not cosmetic. The contract refuses a state that is not strictly
    ascending by `sub`, because that ordering is what makes two peers who
    merged the same envelopes serialize to identical bytes.
    """
    ordered = sorted(entitlements, key=lambda e: e.sub)
    for a, b in zip(ordered, ordered[1:]):
        if a.sub == b.sub:
            raise ValueError(f"two entitlements for one subscriber {a.sub}")
    return {"v": 1, "entitlements": [e.as_json() for e in ordered]}
