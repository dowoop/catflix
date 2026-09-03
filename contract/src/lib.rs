//! # catflix-entitlements — who has been sold a key, and nothing else
//!
//! ## What this contract is for
//!
//! Freenet contract state is PUBLIC. It is replicated to peers who have no
//! relationship with this business and no reason to be trusted by it. So a
//! paywall on Freenet cannot be an access check — there is no gate to stand
//! at. Anybody can read this state, and that is not a defect to be patched.
//!
//! Therefore the cat images are **encrypted**, and this contract holds the
//! only thing that has to change when somebody pays: a per-subscriber
//! envelope carrying the content keys, sealed to that subscriber's X25519
//! public key. A stranger reading every byte of this state learns who holds a
//! subscription and when it expires. They do not learn a content key, because
//! every envelope is sealed to somebody else's key.
//!
//! ## Why the signature is the whole design
//!
//! An envelope is worthless unless it came from the gatekeeper — the process
//! that watched the Tari Ootle chain and saw the money arrive. But a Freenet
//! contract cannot check that for itself.
//!
//! Not because it is a pure function — that is the loose version of the claim
//! and it is false. A 0.2.x contract has host imports for time, randomness and
//! logging, and can ask for related-contract state. The exact defensible claim
//! is narrower and is the one that actually bites: **there is no authenticated
//! view of Tari state available inside a Freenet contract** — no light client,
//! no consensus proof, nothing that could tell a real deposit from a story
//! about one. Until somebody builds that, the bridge is external.
//!
//! So the chain-watching happens off-network, and its verdict arrives here as
//! an **Ed25519 signature**. The gatekeeper's public key is in this contract's
//! PARAMETERS, and parameters are part of the contract address. That is the
//! load-bearing consequence: this contract cannot be re-pointed at a different
//! gatekeeper without becoming a different contract at a different address. A
//! subscriber who bookmarked the address bookmarked the key.
//!
//! ## The merge law
//!
//! Freenet requires that merging states be order-independent, associative and
//! idempotent — a peer receiving updates in a different order must land on the
//! same state. The register is therefore a **join-semilattice**: entitlements
//! keyed by subscriber, and where two entries claim the same subscriber the
//! join takes the one with the higher **issuance sequence** (breaking ties on
//! the signature bytes so the choice is deterministic rather than merely
//! usually-the-same).
//!
//! ### Why `seq` and not the expiry
//!
//! The expiry was the join key until titles became separately purchasable, and
//! then it stopped working. Buying one portrait outright and buying it again
//! produce two entitlements with the SAME far-future expiry, and a join whose
//! key ties has to fall back on signature bytes — so the winner would be
//! whichever envelope happened to sort higher, not the newer one. A subscriber
//! could buy a second portrait and lose it.
//!
//! `seq` is minted by the gatekeeper, one per issuance per subscriber, and
//! only ever increases. Every issuance carries the subscriber's WHOLE set of
//! grants, so "the newest issuance wins" is exactly right: it is a superset of
//! every older one. Replaying an old envelope is then a no-op rather than a
//! downgrade, which is the property the expiry used to provide.
//!
//! ## What this contract deliberately does NOT do
//!
//! - **It does not know the price, the amount paid, or the transaction.** Those
//!   are the gatekeeper's business and belong to the chain, not to a public
//!   replicated store. Putting them here would publish a customer's payment
//!   history to every peer that happens to cache this contract.
//! - **It does not expire anything.** A contract has no clock. `expires_at` is
//!   a number a reader compares against its own clock; this code only ever
//!   compares two expiries against each other. A player whose subscription
//!   lapsed still has their envelope here, and that is correct — they paid for
//!   the epoch it unlocks, and revoking it retroactively would be theft.
//! - **It cannot stop a subscriber sharing their key.** Nothing can. See the
//!   README: this is a paywall, not a DRM scheme, and the difference is stated
//!   there rather than quietly hoped over.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};

/// Bumped only for a change that makes old states unreadable. A reader that
/// does not recognise the version must refuse rather than guess, because a
/// guess here hands somebody a decryption failure they cannot diagnose.
const FORMAT_VERSION: u32 = 1;

/// Domain separation. Without it, a signature this gatekeeper produced for
/// some other purpose — a receipt, a login challenge, anything — could be
/// replayed as an entitlement. The tag is part of the signed bytes on both
/// sides; changing it invalidates every existing envelope, deliberately.
const SIGNING_DOMAIN: &[u8] = b"catflix-entitlement-v1";

/// An X25519 public key, an Ed25519 public key and an Ed25519 signature are
/// all fixed-size. Named rather than spelled inline so a mismatch reads as
/// the wrong thing rather than as a wrong number.
const X25519_PUBLIC_LEN: usize = 32;
const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const AES_GCM_NONCE_LEN: usize = 12;

/// An upper bound on the sealed bundle, checked rather than assumed.
///
/// The sealed blob is chosen by whoever signs it, and the gatekeeper is
/// trusted for CONTENT but should not be trusted for SIZE: a bug in the
/// sealing path that produced a megabyte envelope would be replicated to
/// every peer caching this contract, forever, and no reader could tell it
/// from a legitimate one. 8 KiB is far above a bundle of AES keys and far
/// below anything that costs a peer.
const MAX_SEALED_BYTES: usize = 8 * 1024;

/// A single sold subscription.
///
/// Every field except `sig` is covered by `sig`. That is checked here rather
/// than documented and hoped for: `signing_bytes` is the only place the
/// message is assembled, and both the verifier below and the gatekeeper build
/// it from that same definition.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entitlement {
    /// The subscriber's X25519 public key, base64url. This is the identity —
    /// there is no account, no email and no name, because none of those are
    /// needed to seal a key to somebody and all of them would be published.
    pub sub: String,
    /// The gatekeeper's ephemeral X25519 public key for this envelope,
    /// base64url. Ephemeral per envelope: reusing one across subscribers
    /// would let two of them derive each other's shared secret.
    pub eph: String,
    /// AES-GCM nonce, base64url, 12 bytes.
    pub nonce: String,
    /// The sealed key bundle, base64url. Opaque to this contract by design —
    /// it is ciphertext, and a contract that could read it would be a
    /// contract that had defeated the paywall it exists to serve.
    pub sealed: String,
    /// Unix seconds. Informational; the lattice does not order on it.
    pub issued_at: u64,
    /// The latest moment any grant inside this envelope is good for, or
    /// `PERPETUAL` when one of them never expires. Read by the UI to say
    /// "subscribed until"; the lattice does not order on it.
    pub expires_at: u64,
    /// **The join key.** One per issuance per subscriber, only ever up.
    pub seq: u64,
    /// Ed25519 over `signing_bytes`, base64url, 64 bytes.
    pub sig: String,
}

/// The whole contract state.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Register {
    pub v: u32,
    /// Sorted strictly ascending by `sub`, which is both the dedup rule and
    /// the canonical ordering. Two peers that merged the same set of
    /// envelopes therefore serialize to identical bytes, so a state hash
    /// means something.
    pub entitlements: Vec<Entitlement>,
}

/// A delta is the same shape as a state: a set of envelopes to join in.
/// Keeping one shape means `update_state` has one code path whether it was
/// handed a delta, a full state, or a merge of several.
type Delta = Register;

impl Entitlement {
    /// The exact bytes an Ed25519 signature commits to.
    ///
    /// Fixed-width fields are concatenated; the one variable-length field
    /// (`sealed`) carries a 4-byte big-endian length ahead of it. That is not
    /// decoration: without it, a signature over (sealed=A, then some fixed
    /// field B) could be reinterpreted as (sealed=A||B', ...) for a different
    /// split, and two different entitlements would share one valid signature.
    fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let sub = decode_fixed(&self.sub, X25519_PUBLIC_LEN, "sub")?;
        let eph = decode_fixed(&self.eph, X25519_PUBLIC_LEN, "eph")?;
        let nonce = decode_fixed(&self.nonce, AES_GCM_NONCE_LEN, "nonce")?;
        let sealed = B64
            .decode(&self.sealed)
            .map_err(|_| invalid("sealed is not base64url"))?;
        if sealed.is_empty() || sealed.len() > MAX_SEALED_BYTES {
            return Err(invalid("sealed bundle is empty or larger than this contract accepts"));
        }

        let mut msg = Vec::with_capacity(
            SIGNING_DOMAIN.len() + X25519_PUBLIC_LEN * 2 + AES_GCM_NONCE_LEN + 4 + sealed.len() + 16,
        );
        msg.extend_from_slice(SIGNING_DOMAIN);
        msg.extend_from_slice(&sub);
        msg.extend_from_slice(&eph);
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        msg.extend_from_slice(&sealed);
        msg.extend_from_slice(&self.issued_at.to_be_bytes());
        msg.extend_from_slice(&self.expires_at.to_be_bytes());
        msg.extend_from_slice(&self.seq.to_be_bytes());
        Ok(msg)
    }

    /// Is this envelope really from the gatekeeper this contract is bound to?
    fn verify(&self, gatekeeper: &VerifyingKey) -> Result<(), ContractError> {
        let msg = self.signing_bytes()?;
        let raw = decode_fixed(&self.sig, ED25519_SIGNATURE_LEN, "sig")?;
        let mut bytes = [0u8; ED25519_SIGNATURE_LEN];
        bytes.copy_from_slice(&raw);
        gatekeeper
            .verify_strict(&msg, &Signature::from_bytes(&bytes))
            .map_err(|_| invalid("an entitlement is not signed by this contract's gatekeeper"))
    }
}

/// Read the gatekeeper's key out of the contract parameters.
///
/// Parameters are part of the contract address, so this is where "which
/// business is this?" is actually decided. A malformed or non-canonical key
/// is a refusal, never a default: defaulting here would silently accept
/// envelopes from nobody in particular.
fn gatekeeper_key(parameters: &Parameters<'_>) -> Result<VerifyingKey, ContractError> {
    let bytes = parameters.as_ref();
    if bytes.len() != ED25519_PUBLIC_LEN {
        return Err(invalid(
            "parameters must be exactly the gatekeeper's 32-byte Ed25519 public key",
        ));
    }
    let mut key = [0u8; ED25519_PUBLIC_LEN];
    key.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&key)
        .map_err(|_| invalid("the gatekeeper key in parameters is not a valid Ed25519 point"))
}

fn decode_fixed(field: &str, want: usize, name: &str) -> Result<Vec<u8>, ContractError> {
    let raw = B64
        .decode(field)
        .map_err(|_| invalid_owned(format!("{name} is not base64url")))?;
    if raw.len() != want {
        return Err(invalid_owned(format!(
            "{name} must decode to exactly {want} bytes"
        )));
    }
    Ok(raw)
}

fn invalid(reason: &str) -> ContractError {
    ContractError::InvalidUpdateWithInfo {
        reason: reason.to_string(),
    }
}

fn invalid_owned(reason: String) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason }
}

/// Parse a register and check every claim it makes.
///
/// An empty byte string is the empty register, so a freshly published
/// contract with no state is legal rather than a parse error a caller has to
/// special-case.
fn parse_checked(bytes: &[u8], gatekeeper: &VerifyingKey) -> Result<Register, ContractError> {
    if bytes.is_empty() {
        return Ok(Register {
            v: FORMAT_VERSION,
            entitlements: Vec::new(),
        });
    }
    let register: Register =
        serde_json::from_slice(bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
    if register.v != FORMAT_VERSION {
        return Err(invalid_owned(format!(
            "state format version {} is not {FORMAT_VERSION}; refusing to guess",
            register.v
        )));
    }
    // Strictly ascending is both "no duplicate subscribers" and "canonical
    // order". Checked with a window rather than by sorting a copy, so a state
    // that is merely unsorted is refused rather than quietly repaired -- a
    // repair here would make two peers disagree about the state's hash.
    for pair in register.entitlements.windows(2) {
        if pair[0].sub >= pair[1].sub {
            return Err(invalid(
                "entitlements must be strictly ascending by subscriber key",
            ));
        }
    }
    for entitlement in &register.entitlements {
        entitlement.verify(gatekeeper)?;
    }
    Ok(register)
}

/// The join. Higher issuance sequence wins; ties break on signature bytes.
///
/// The tie-break is what makes this a function rather than a preference. Two
/// envelopes for one subscriber with equal `seq` are both valid and the
/// network must pick the same one on every peer, so the rule cannot be "keep
/// the one that arrived first".
fn join(into: &mut BTreeMap<String, Entitlement>, incoming: Vec<Entitlement>) {
    for candidate in incoming {
        match into.get(&candidate.sub) {
            Some(existing) if (existing.seq, &existing.sig) >= (candidate.seq, &candidate.sig) => {}
            _ => {
                into.insert(candidate.sub.clone(), candidate);
            }
        }
    }
}

fn serialize(map: BTreeMap<String, Entitlement>) -> Result<Vec<u8>, ContractError> {
    // BTreeMap iterates in key order, which is exactly the canonical order
    // `parse_checked` demands. The two facts are one fact, and separating
    // them is how canonical orderings drift.
    let register = Register {
        v: FORMAT_VERSION,
        entitlements: map.into_values().collect(),
    };
    serde_json::to_vec(&register).map_err(|e| ContractError::Deser(e.to_string()))
}

struct CatflixEntitlements;

#[contract]
impl ContractInterface for CatflixEntitlements {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let gatekeeper = match gatekeeper_key(&parameters) {
            Ok(key) => key,
            // A contract whose parameters are not a key can never hold a valid
            // state. Invalid, not an error: the peer asked a question and this
            // is the answer, not a failure to answer.
            Err(_) => return Ok(ValidateResult::Invalid),
        };
        match parse_checked(state.as_ref(), &gatekeeper) {
            Ok(_) => Ok(ValidateResult::Valid),
            Err(_) => Ok(ValidateResult::Invalid),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let gatekeeper = gatekeeper_key(&parameters)?;
        let current = parse_checked(state.as_ref(), &gatekeeper)?;

        let mut merged: BTreeMap<String, Entitlement> = current
            .entitlements
            .into_iter()
            .map(|e| (e.sub.clone(), e))
            .collect();

        for update in data {
            // Every branch runs the incoming bytes through `parse_checked`,
            // so an unsigned or wrongly-signed envelope is refused no matter
            // which shape it arrived in. A delta is not a lesser thing than a
            // state and is not trusted more cheaply.
            let incoming: Delta = match update {
                UpdateData::State(s) => parse_checked(s.as_ref(), &gatekeeper)?,
                UpdateData::Delta(d) => parse_checked(d.as_ref(), &gatekeeper)?,
                UpdateData::StateAndDelta { state, delta } => {
                    let mut both = parse_checked(state.as_ref(), &gatekeeper)?;
                    both.entitlements
                        .extend(parse_checked(delta.as_ref(), &gatekeeper)?.entitlements);
                    both
                }
                // This contract is self-contained: it needs no related
                // contract to decide whether an envelope is genuine, because
                // the only thing that decides that is a signature it can
                // already check. Refusing is honest; pretending to handle a
                // shape that cannot occur here is not.
                _ => return Err(invalid("this contract takes states and deltas only")),
            };
            join(&mut merged, incoming.entitlements);
        }

        Ok(UpdateModification::valid(serialize(merged)?.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let gatekeeper = gatekeeper_key(&parameters)?;
        let register = parse_checked(state.as_ref(), &gatekeeper)?;
        // Subscriber and sequence only. That is everything needed to decide
        // what a peer is missing, and it is a fraction of the size of the
        // envelopes themselves -- which is the entire point of a summary.
        let summary: Vec<(String, u64)> = register
            .entitlements
            .into_iter()
            .map(|e| (e.sub, e.seq))
            .collect();
        Ok(serde_json::to_vec(&summary)
            .map_err(|e| ContractError::Deser(e.to_string()))?
            .into())
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let gatekeeper = gatekeeper_key(&parameters)?;
        let register = parse_checked(state.as_ref(), &gatekeeper)?;

        // An absent or unreadable summary means "I have nothing" rather than
        // an error. A peer that cannot phrase what it holds still needs the
        // state, and failing here would strand it.
        let theirs: BTreeMap<String, u64> = if summary.as_ref().is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_slice::<Vec<(String, u64)>>(summary.as_ref())
                .map(|pairs| pairs.into_iter().collect())
                .unwrap_or_default()
        };

        let missing: Vec<Entitlement> = register
            .entitlements
            .into_iter()
            .filter(|e| match theirs.get(&e.sub) {
                Some(&seq) => e.seq > seq,
                None => true,
            })
            .collect();

        // Nothing missing is the EMPTY byte string, not an empty register.
        // `fdev verify-merge` flagged this: a 25-byte `{"v":1,...}` sent to a
        // peer that already has everything is 25 bytes of pure overhead on
        // the commonest synchronisation there is -- two peers already in
        // agreement. `parse_checked` reads empty bytes as the empty register,
        // so the receiving side needs no special case.
        if missing.is_empty() {
            return Ok(Vec::new().into());
        }
        let delta = Register {
            v: FORMAT_VERSION,
            entitlements: missing,
        };
        Ok(serde_json::to_vec(&delta)
            .map_err(|e| ContractError::Deser(e.to_string()))?
            .into())
    }
}
