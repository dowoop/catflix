//! # catflix-requests — the queue a sandboxed page can shout into
//!
//! ## The problem this solves, which is not the one it looks like
//!
//! A Freenet web container runs in a sandboxed iframe. Nothing outside it can
//! read it: not another page, not the operator, and — measured here — not the
//! browser-automation tooling or the console reader either. That is a good
//! property and it is not negotiable.
//!
//! It also means a visitor who wants the house to pay for them has no way to
//! tell the house *which order to pay*. The order reference exists only inside
//! the sandbox. Copy-and-paste works for a human with a wallet; it does not
//! work for "press this button and watch some cats", which is the whole point
//! of a demo somebody can try with nothing installed.
//!
//! So the reference travels out through the only channel the page actually
//! has: **Freenet itself.** The page writes its reference into this contract,
//! and the operator reads it from the other side. No HTTP endpoint, no CORS,
//! no server to run, and nothing that stops working when the operator sleeps.
//!
//! ## Why this one is unsigned, on purpose
//!
//! The entitlement contract refuses everything not signed by the gatekeeper,
//! because an entry there IS access. An entry here is a *request*, and a
//! request that had to be authorised before it could be made would need the
//! authoriser to already know who was asking — which is the thing the visitor
//! has no way to arrange.
//!
//! So anybody may write here, and the protection is that writing costs the
//! writer something and gains them nothing: the house decides what it pays,
//! how much, and how often. A queue full of junk references is a queue the
//! house declines. The bound that matters is on the SET, not on the writer.
//!
//! ## The two bounds, both refusals
//!
//! - every entry must be shaped like a Catflix reference and fit the payment
//!   component's own 128-byte limit, so this cannot be used as free storage
//! - the set is capped, so a contract that anybody may append to cannot be
//!   grown without limit by somebody who simply keeps appending
//!
//! Growth is the honest weakness: entries are never removed, because removal
//! from a replicated grow-only set needs tombstones, and a tombstone anybody
//! may write is a censorship button anybody may press. At the cap this
//! contract stops accepting, which is a refusal the operator can see rather
//! than a silent failure the visitor discovers.

use std::collections::BTreeSet;

use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};

const FORMAT_VERSION: u32 = 1;
const PREFIX: &str = "CF1.";
/// The payment component's own bound. Matching it means a reference that fits
/// here is one that can actually be paid.
const MAX_REFERENCE: usize = 128;
/// Above this the queue stops accepting. Sized so the whole set stays a few
/// hundred kilobytes -- small enough to replicate, large enough that a real
/// demo never reaches it.
const MAX_ENTRIES: usize = 2000;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Queue {
    pub v: u32,
    /// Sorted, unique. The ordering is the dedup rule and the canonical form,
    /// so two peers holding the same requests serialize identically.
    pub refs: Vec<String>,
}

fn invalid(reason: &str) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason: reason.to_string() }
}

/// `CF1.<key>.<sku>.<freshness>` — FOUR parts.
///
/// It was three until a portrait became separately orderable and the SKU had
/// to travel with the money. This function was not updated with it, so the
/// queue silently refused every reference the site now produces: the "let the
/// house pay" button hung with its promise neither resolved nor rejected, and
/// the visitor was told nothing at all. A shape check in one contract that
/// mirrors a format owned by another is a thing that goes stale quietly —
/// which is why the bound below is on the SIZE, and the meaning is checked by
/// the gatekeeper that actually owns the format.
fn well_formed(reference: &str) -> bool {
    reference.len() <= MAX_REFERENCE
        && reference.starts_with(PREFIX)
        && reference.split('.').count() == 4
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn parse(bytes: &[u8]) -> Result<Queue, ContractError> {
    if bytes.is_empty() {
        return Ok(Queue { v: FORMAT_VERSION, refs: Vec::new() });
    }
    let queue: Queue = serde_json::from_slice(bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
    if queue.v != FORMAT_VERSION {
        return Err(invalid("unrecognised queue format version"));
    }
    if queue.refs.len() > MAX_ENTRIES {
        return Err(invalid("the request queue is full"));
    }
    for pair in queue.refs.windows(2) {
        if pair[0] >= pair[1] {
            return Err(invalid("requests must be strictly ascending and unique"));
        }
    }
    if let Some(bad) = queue.refs.iter().find(|r| !well_formed(r)) {
        return Err(invalid(match bad.len() > MAX_REFERENCE {
            true => "a request is longer than the payment component accepts",
            false => "a request is not shaped like a Catflix reference",
        }));
    }
    Ok(queue)
}

fn serialize(set: BTreeSet<String>) -> Result<Vec<u8>, ContractError> {
    if set.len() > MAX_ENTRIES {
        return Err(invalid("the request queue is full"));
    }
    serde_json::to_vec(&Queue { v: FORMAT_VERSION, refs: set.into_iter().collect() })
        .map_err(|e| ContractError::Deser(e.to_string()))
}

struct CatflixRequests;

#[contract]
impl ContractInterface for CatflixRequests {
    fn validate_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        Ok(match parse(state.as_ref()) {
            Ok(_) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let mut set: BTreeSet<String> = parse(state.as_ref())?.refs.into_iter().collect();
        for update in data {
            let incoming = match update {
                UpdateData::State(s) => parse(s.as_ref())?,
                UpdateData::Delta(d) => parse(d.as_ref())?,
                UpdateData::StateAndDelta { state, delta } => {
                    let mut both = parse(state.as_ref())?;
                    both.refs.extend(parse(delta.as_ref())?.refs);
                    both
                }
                _ => return Err(invalid("this contract takes states and deltas only")),
            };
            // Union. Never removal -- that is what makes arrival order and
            // duplicate delivery irrelevant, which is what the network needs.
            set.extend(incoming.refs);
        }
        Ok(UpdateModification::valid(serialize(set)?.into()))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let queue = parse(state.as_ref())?;
        Ok(serde_json::to_vec(&queue.refs)
            .map_err(|e| ContractError::Deser(e.to_string()))?
            .into())
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let queue = parse(state.as_ref())?;
        let theirs: BTreeSet<String> = if summary.as_ref().is_empty() {
            BTreeSet::new()
        } else {
            serde_json::from_slice::<Vec<String>>(summary.as_ref())
                .map(|v| v.into_iter().collect())
                .unwrap_or_default()
        };
        let missing: Vec<String> = queue.refs.into_iter().filter(|r| !theirs.contains(r)).collect();
        if missing.is_empty() {
            return Ok(Vec::new().into());
        }
        Ok(serde_json::to_vec(&Queue { v: FORMAT_VERSION, refs: missing })
            .map_err(|e| ContractError::Deser(e.to_string()))?
            .into())
    }
}
