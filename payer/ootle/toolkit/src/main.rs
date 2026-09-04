//! # toolkit — an Ootle account, the faucet, and a template on esmeralda
//!
//! **A workstation tool. Not part of the terminal**, which stays stdlib-only
//! Python. This binary is what a session uses to put a template on a real
//! network and call it, and it exists because the alternative was the wallet
//! daemon's Web UI — `tari_ootle_walletd` is not published to crates.io and
//! would need a source build, while `ootle-rs` talks to the indexer directly
//! with a local keypair. The UI path costs more setup, not less.
//!
//! Publishing programmatically overrides the vendored skill, which says in
//! capitals not to. That override is the maintainer's, dated 2026-07-27, on the stated
//! grounds that this is testnet and nothing is in circulation — and the reason
//! is also its boundary: **it does not survive contact with mainnet**, which
//! is a non-working mode by decision anyway.
//!
//! ## Everything here was read from crate source, not from documentation
//!
//! That is not a boast, it is the operating rule this repo arrived at the
//! expensive way, and this file is where it paid twice:
//!
//! * **`take_faucet_funds()` takes NO argument.** It dispenses a fixed amount
//!   via the faucet component's `take`. The vendored skill shows
//!   `take_faucet_funds(10 * TARI)`, and `ootle-rs`'s own rustdoc —
//!   `lib.rs:45` and `builtin_templates/faucet.rs:41` — shows
//!   `take_free_coins(500_000_000u64)`, **a method that exists nowhere in the
//!   crate** (grepped, 2026-07-28: those two doc comments are its only
//!   occurrences). Three documents describe this call and two are wrong,
//!   including the library's own.
//!
//! * **The documented ORDER cannot work for a new account**, and this is the
//!   sharper one because it would compile. Both docs show
//!   `.pay_fee(…).take_free_coins(…)`. Read `faucet.rs:88`: `pay_fee` checks
//!   whether `account_workspace_name` is already set and pays from the
//!   on-chain account address when it is not. `take_faucet_funds()` is what
//!   sets that name — it emits `create_account` first and hands back a
//!   workspace slot. So calling `pay_fee` **first** asks a brand-new signer's
//!   account, which does not exist yet, to pay the fee for the transaction
//!   that creates it. This tool calls `take_faucet_funds()` first, and that
//!   ordering is the whole reason a first faucet call can succeed at all.
//!
//! ## What it does not do
//!
//! No mainnet: `Network::Esmeralda` is a constant, not a flag. No sweep, no
//! transfer, no key export — this account holds testnet XTR whose only job is
//! paying publish fees, and every extra verb is another way to lose it.

use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

// `args!` and `Workspace` come from the transaction crate directly. ootle-rs
// does not re-export them (it does `use tari_ootle_transaction::{..., args}`
// internally, `account.rs:8`), so this crate names the same source rather than
// reaching through a private path.
use tari_ootle_transaction::args;
// AT MODULE SCOPE because `check_signing_response` is a free function that the
// tests call, not a block inside `main`. The two verbs that use these keep
// their local `use` lines; a second import of the same path is free and the
// alternative is editing two working blocks for no behaviour.
use tari_ootle_transaction::{Epoch, TransactionSignature, UnsignedTransaction};

// `want_substate` takes this, and ootle-rs re-exports only `displayable` out of
// this crate — so it is named here rather than reached through
// `ootle_rs::...::engine_types`, which is a path ootle-rs uses internally and
// does not promise. See the Cargo.toml note for why `loyalty redeem` needs it.
use tari_ootle_common_types::engine_types::substate::SubstateId;

use ootle_rs::{
    Network, TransactionRequest,
    // `TransactionBuildable` is where `.then()` lives - the escape hatch for
    // instructions the typed builders do not wrap, which is every call to a
    // template this repo publishes. Named from `faucet.rs:28`, where ootle-rs
    // imports it the same way.
    builtin_templates::{
        UnsignedTransactionBuilder,
        account::IAccount,
        component::{IComponent, TransactionBuildable},
        faucet::IFaucet,
    },
    key_provider::PrivateKeyProvider,
    keys::OotleSecretKey,
    // The address and amount types the templates are compiled against.
    // ootle-rs re-exports the whole crate as `template_types` (`lib.rs:163`),
    // so these are the SAME types the contract sees rather than look-alikes.
    template_types::{
        Amount, ComponentAddress, NonFungibleAddress, NonFungibleId, ResourceAddress, VaultId,
        crypto::RistrettoPublicKeyBytes,
    },
    // `to_account_address` is a trait method, not inherent - an Ootle
    // ADDRESS and the ACCOUNT COMPONENT it owns are different things, and
    // the derivation between them lives in this trait (`types/address.rs:18`).
    ToAccountAddress,
    provider::{ProviderBuilder, WalletProvider},
    wallet::OotleWallet,
};

/// How many epochs ahead a built transaction stays sequenceable.
///
/// `max_epoch` is the last epoch a transaction may be sequenced in, and
/// ootle-rs 0.21 made it a REQUIRED argument to every `I*::new`. 0.16 left the
/// field null, and esmeralda's 0.39.3 indexer refuses that outright:
///
///     Failed to decode transaction: unexpected type null at position 251:
///     expected u64
///
/// which is what `toolkit faucet` returned on the old build. So this is not a
/// tunable so much as the fix.
///
/// Ten epochs is a little under nine hours at the ~53 minutes this network has
/// averaged (indexer `/network` read 9847 on 2026-07-27, 10092 on 2026-08-05,
/// 10765 on 2026-08-30). Far longer than any verb here takes, and it still
/// bounds a transaction that is composed and never submitted.
const MAX_EPOCH_WINDOW: u64 = 10;

/// How long the provider waits for a transaction to finalise before giving up.
///
/// The ootle-rs default is 32 s (`PendingTransaction::DEFAULT_TX_TIMEOUT`), and
/// the skill says that is often too short on Esmeralda. Finality measurement
/// is the one place where the wait itself is the thing under study, so this is
/// deliberately generous: a sample that hits the ceiling is recorded as a
/// timeout rather than discarded, and 120 s is the skill's recommended
/// testnet budget.
const TX_TIMEOUT: Duration = Duration::from_secs(120);

/// esmeralda, and only esmeralda.
///
/// A `--network` flag would be the single cheapest way to point this at
/// mainnet by accident, and mainnet is a non-working mode by decision. When
/// that decision changes this becomes an argument; until then it is a
/// constant, and the absence of the flag is the promise.
const NETWORK: Network = Network::Esmeralda;

/// Fee budgets, in XTR units.
///
/// **The honest cost of skipping the Web UI is fee ESTIMATION** — estimating
/// is what the UI's button does and this tool has no equivalent. The skill
/// puts a typical template publish at 150k–250k units, so `PUBLISH_FEE` sits
/// deliberately above that band rather than inside it: an under-budgeted
/// publish fails *and still spends the attempt*.
/// **Measured 2026-08-30 on esmeralda at 0.39.3: the faucet required 2,182.**
/// At 1,000 it returned `Reject(InsufficientFeesPaid("Insufficient fees paid:
/// 1000, required fees: 2182"))` -- the transaction was accepted, executed and
/// rejected on economics, which is the attempt spent for nothing that the note
/// above warns about. The margin is deliberate for the same reason
/// `PUBLISH_FEE` is extravagant: on a testnet the units are free and a failed
/// attempt is not.
const FAUCET_FEE: u64 = 20_000;

/// The merchant's account-opening policy, out of the file they already own.
///
/// **The defaults here are the ones `merchant.py` declares**, duplicated
/// rather than shared because the two programs are written in different
/// languages and there is no honest way to share a constant between them. The
/// duplication is the cost; `h_open_account.py` asserts the two agree, so a
/// drift fails the sweep rather than being discovered as a spend nobody
/// expected.
///
/// WHY THE AMOUNT IS TRIVIAL BY DEFAULT, kept from the constant this replaced:
/// what is being bought is the EXISTENCE of the account, not a balance. An
/// Ootle account is a component, creating one is a transaction, and a customer
/// who has never held XTR cannot pay for it — so a shop that wants to award
/// them anything opens it and pays. A default large enough to be worth
/// stealing would turn the least interesting act at the counter into one
/// somebody has to think about.
///
/// **A SETTING NOTHING READ WOULD BE DECORATION.** `merchant.py` gained
/// `open_account_amount` / `open_account_per_day` on 2026-08-15 and the
/// terminal renders both — but the terminal does not open accounts, this
/// binary does. A limit displayed on one program and ignored by the one that
/// spends is worse than no limit: it tells an operator a number is being
/// honoured when nothing is honouring it.
///
/// Read at call time and never cached, so an operator who has just lowered the
/// figure does not have to restart anything to have meant it.
///
/// **CLAMPED, NOT REFUSED, and the safe direction is DOWN.** This runs in
/// front of a spend. A missing file, an unparseable one, or a value out of
/// range all fall back to the same conservative default the terminal uses,
/// because a tool that refused to open an account over a malformed config
/// would be a tool that stops a shop serving a customer over a typo.
fn open_account_policy() -> (u64, u64) {
    const DEFAULT_AMOUNT: u64 = 1;
    const MAX_AMOUNT: u64 = 1_000_000;
    const DEFAULT_PER_DAY: u64 = 25;
    const MAX_PER_DAY: u64 = 500;

    let read = |key: &str, default: u64, ceiling: u64| -> u64 {
        let Ok(home) = std::env::var("HOME") else {
            return default;
        };
        let path = PathBuf::from(home).join(".cryptopos_learning/merchant.json");
        let Ok(raw) = fs::read_to_string(path) else {
            return default;
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return default;
        };
        match doc.get("ootle").and_then(|o| o.get(key)).and_then(|v| v.as_u64()) {
            Some(value) if value <= ceiling => value,
            Some(_) => ceiling,
            None => default,
        }
    };
    (
        read("open_account_amount", DEFAULT_AMOUNT, MAX_AMOUNT),
        read("open_account_per_day", DEFAULT_PER_DAY, MAX_PER_DAY),
    )
}

/// A publish budget. **Deliberately extravagant, and that is the measured
/// strategy rather than laziness.**
///
/// The first version of this function was `4 * bytes + 100_000`, fitted to one
/// template. A second template refuted it inside an hour:
///
/// ```text
///  83,737 bytes ->   290,820 units   (3.473 / byte)   epoch_probe
/// 196,946 bytes -> 2,655,120 units  (13.481 / byte)   gift_card
/// ```
///
/// 2.35x the size cost 9.13x the fee. **Publish cost is not linear in size**,
/// and two points fit any two-parameter law, so no law is asserted here — the
/// implied exponent of ~2.59 is a curiosity, not a model.
///
/// **What makes a model unnecessary is an asymmetry in the fee receipts:**
///
/// ```text
/// committed: total_fee_payment 434,948   total_fees_paid 334,858   overcharge 0
/// refused  : total_fee_payment 300,000   total_fees_paid 300,000
/// ```
///
/// **Overpaying is free — the surplus is not taken. Underpaying costs the
/// entire budget and publishes nothing.** So the expected cost of guessing
/// high is zero and the expected cost of guessing tight is the whole attempt.
/// Under those payoffs the correct budget is not the best estimate; it is a
/// number comfortably past any plausible estimate. Hence 20 units a byte
/// against a worst observed 13.5, and 500k of floor for the size-independent
/// remainder (`TransactionWeight` and `ExhaustBurn`, which between them were
/// 200k on the larger template).
///
/// This is the reverse of how the rest of this repo budgets, and the reverse
/// is right here: a rate lock is tightened because being wrong costs the
/// merchant money, while a fee budget is loosened because being wrong costs
/// the merchant money. Same principle, opposite direction.
///
/// ⚠ **AND "GENEROUS" WAS NOT ENOUGH, BECAUSE IT WAS THE WRONG SHAPE.**
/// Measured 2026-08-04, publishing `loyalty` at 316,511 bytes: required
/// 8,316,562 against a budget of 6,830,220, refused, and the whole 6,830,220
/// taken. The paragraph above dismissed the exponent as "a curiosity, not a
/// model" and set a LINEAR budget with a 1.5x margin over the worst per-byte
/// figure then known. Three measurements now:
///
/// ```text
///   bytes    TemplatePublish   per byte   fee / bytes^2
///  83,737            290,820       3.47       4.15e-05
/// 196,946          2,655,120      13.48       6.85e-05
/// 316,511          7,814,820      24.69       7.80e-05
/// ```
///
/// Per-byte doubles each time; **fee / bytes² converges on ~8e-5**. The cost
/// is quadratic, so a linear budget's margin SHRINKS as templates grow and is
/// overtaken by whichever one crosses the line. 20/byte was already below the
/// 24.69 this template actually cost before it was ever submitted.
///
/// The lesson is not "pick a bigger constant" — that is the same mistake with
/// a longer fuse. **A budget must have the same shape as the cost it is
/// covering, or its safety margin is a function of size and expires without
/// anyone deciding it should.** The quadratic term below is set at 1.5e-4,
/// roughly twice the observed coefficient, so the 2x margin now holds at
/// every size instead of only at small ones.
fn publish_fee(wasm_len: usize) -> u64 {
    let n = wasm_len as u64;
    // n^2 * 3 / 20_000 is 1.5e-4 * n^2 in integer arithmetic. At 316,511 bytes
    // that is ~15.0M, against 8.3M actually required.
    n * n * 3 / 20_000 + n * 20 + 500_000
}
/// A function call executes and stores nothing, so it is nowhere near a
/// publish. Still budgeted generously rather than tightly: a rejected call
/// costs the attempt and teaches nothing.
/// **Measured 2026-08-31 on esmeralda at 0.39.3: a `loyalty deploy` required
/// 6,705 and this constant was 5,000**, so the deploy came back
/// `OnlyFeeCommit(InsufficientFeesPaid("Required fees 6705 but 5000 paid"))` --
/// the fee taken, the component not created. The same stale-constant shape as
/// `FAUCET_FEE` above, and the same remedy: budget well over the measurement,
/// because an unused budget is refunded (`total_fee_overcharge: 0`) while an
/// insufficient one spends the attempt.
const CALL_FEE: u64 = 50_000;

/// Where the keypair lives.
///
/// Outside the repository on purpose. It is testnet material and valueless,
/// but a secret committed to git is a habit rather than a risk assessment, and
/// this one sits beside the terminal's other state instead. It is recorded in
/// `FUNDS_AND_CREDENTIALS.md`, whose job is accounting rather than secrecy.
fn key_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME is not set");
    PathBuf::from(home).join(".cryptopos_learning/ootle_toolkit_key.json")
}

/// A key file that has been sealed with a passphrase.
///
/// ## WHAT THIS BUYS, AND WHAT IT DOES NOT — read both halves
///
/// **It buys:** a till that is stolen, a disk that is resold, a backup that
/// leaks, or a laptop taken while powered off no longer hands over the
/// merchant's account. That is the case the maintainer asked for on 2026-08-14 — "if it
/// is on the point of sale device I would like to make it encrypted somehow so
/// that theft is manageable" — and it is the case that turns a total, permanent
/// compromise into a recoverable inconvenience.
///
/// **It does not buy** protection from a compromised RUNNING till. The key has
/// to be plaintext in memory to sign, and this binary signs on demand, so
/// anything executing as this user while the passphrase is available can read
/// it. `OOTLE_KEY_PASSPHRASE` in particular is readable by any process of the
/// same user. Encryption at rest is a defence against *possession of the
/// hardware*, and it is not a defence against *code running on it*.
///
/// **What this used to be worth, and what changed on 2026-08-14.** Until K1
/// landed, the key in this file could never be rotated: `Loyalty::new` captured
/// `transaction_signer_public_key()` and baked it into seven method rules under
/// `OwnerRule::None`, so a theft of it was permanent and the only remedy was
/// abandoning the component and stranding every point every customer holds.
/// Sealing was the only mitigation available and it was a thin one.
///
/// The key this file holds is now the **operating** key, and it is replaceable:
/// `rotate_operating_key`, gated by a recovery key that must never be on this
/// machine, retires it any number of times. So sealing has changed shape — it
/// still defends only against possession of the hardware, but a failure of that
/// defence is now survivable rather than terminal, and a lost passphrase costs
/// a rotation rather than the programme. See `board/IN_PROGRESS.md` K1.
#[derive(serde::Serialize, serde::Deserialize)]
struct SealedKey {
    /// Present and equal to `argon2id` so a future format is a refusal rather
    /// than a misparse. A file whose KDF this build does not recognise must not
    /// be opened with a guess.
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
    network: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKey {
    /// Signs transactions and owns the account.
    account_secret: String,
    /// Derives stealth secrets. Stored beside the account key because
    /// `OotleSecretKey` holds both, and regenerating either one produces a
    /// different address — losing the account rather than reopening it.
    view_only_secret: String,
    network: String,
}

/// Load the keypair, creating it on first run.
///
/// **Refuses rather than overwrites.** A key file that exists but will not
/// parse is the one case where the tempting behaviour — generate a fresh key
/// and carry on — silently abandons an account that may hold the only funded
/// balance on this workstation. Same shape as `merchant.py`'s refusal on an
/// unparseable `merchant.json`, and for the same reason.
fn load_or_create_key() -> Result<OotleSecretKey, Box<dyn std::error::Error>> {
    load_or_create_key_at(key_path())
}

/// Hex, by hand.
///
/// `tari_utilities` has this, reached through two re-exports whose stability
/// this crate has already been bitten by once. Sixteen characters of lookup is
/// cheaper than a path that may move.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// The passphrase, from the environment or from a terminal.
///
/// **The environment variable is the till's path and it is a deliberate
/// weakening.** A terminal that must award points after every sale cannot stop
/// to ask a human for a passphrase, so the operator exports it once at the
/// start of a shift and the sidecar inherits it. Any process running as the
/// same user can read `/proc/<pid>/environ`, which is exactly why the module
/// docs on `SealedKey` say this protects the hardware and not the running
/// system. Stated here rather than left for someone to discover.
///
/// **When there is no variable and there IS a terminal, it asks** — with echo
/// off through `stty`, because a passphrase typed onto a shared screen at a
/// counter is not a passphrase. Unix-only and not behind a portability shim,
/// for the same reason `restrict` is not: this repository runs on Linux, and a
/// `#[cfg]` that silently skipped the echo suppression elsewhere would be a
/// promise the terminal does not keep.
fn passphrase(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(from_env) = std::env::var("OOTLE_KEY_PASSPHRASE") {
        if !from_env.is_empty() {
            return Ok(from_env);
        }
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err("the key file is sealed and there is no terminal to ask on. \
                    Set OOTLE_KEY_PASSPHRASE, and read what that costs in the \
                    `SealedKey` docs before you put it in a shell profile."
            .into());
    }
    eprint!("{prompt}: ");
    let echo_off = std::process::Command::new("stty").arg("-echo").status();
    let mut line = String::new();
    let read = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line);
    if echo_off.map(|s| s.success()).unwrap_or(false) {
        let _ = std::process::Command::new("stty").arg("echo").status();
    }
    eprintln!();
    read?;
    Ok(line.trim_end_matches('\n').to_string())
}

/// argon2id over the passphrase, into the AEAD's 32 bytes.
///
/// Default parameters on purpose. They are the crate's recommended set, and a
/// hand-tuned cost here would be a number nobody could justify later against
/// hardware nobody has measured.
fn derive(pass: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use argon2::Argon2;
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2 refused to derive a key ({e})"))?;
    Ok(out)
}

fn seal(stored: &StoredKey, pass: &str) -> Result<SealedKey, Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
        ChaCha20Poly1305, Nonce,
    };
    use zeroize::Zeroize;

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut derived = derive(pass, &salt)?;
    let cipher = ChaCha20Poly1305::new((&derived).into());
    let mut plain = serde_json::to_vec(stored)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|e| format!("sealing failed ({e})"))?;
    plain.zeroize();
    derived.zeroize();

    Ok(SealedKey {
        kdf: "argon2id".into(),
        salt: to_hex(&salt),
        nonce: to_hex(&nonce),
        ciphertext: to_hex(&ciphertext),
        network: stored.network.clone(),
    })
}

fn unseal(sealed: &SealedKey, pass: &str) -> Result<StoredKey, Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use zeroize::Zeroize;

    // A format this build does not know is a REFUSAL. Opening it by assuming
    // the current KDF would either fail confusingly or, worse, succeed against
    // a file written by something else.
    if sealed.kdf != "argon2id" {
        return Err(format!(
            "this key file says its KDF is `{}`, which this build does not know. \
             Refusing to guess.",
            sealed.kdf
        )
        .into());
    }
    let salt = from_hex(&sealed.salt).map_err(|e| format!("salt is not hex ({e})"))?;
    let nonce = from_hex(&sealed.nonce).map_err(|e| format!("nonce is not hex ({e})"))?;
    let blob = from_hex(&sealed.ciphertext).map_err(|e| format!("ciphertext is not hex ({e})"))?;

    let mut derived = derive(pass, &salt)?;
    let cipher = ChaCha20Poly1305::new((&derived).into());
    let opened = cipher.decrypt(Nonce::from_slice(&nonce), blob.as_slice());
    derived.zeroize();

    // THE TAG IS THE WHOLE POINT OF PICKING AN AEAD. A wrong passphrase fails
    // here rather than producing 32 bytes that look like a secret key and would
    // derive a stranger's account — an error a user would read as "my funds are
    // gone" rather than "I typed it wrong".
    let mut plain = opened.map_err(|_| {
        "that passphrase does not open this key file. Nothing was changed."
            .to_string()
    })?;
    let stored: StoredKey = serde_json::from_slice(&plain)?;
    plain.zeroize();
    Ok(stored)
}

/// The DEV BENCH's customer key. **This is not a customer's key and no surface
/// may describe it as one.**
///
/// It exists so the co-signature path can be exercised end to end on esmeralda:
/// `enroll` and `redeem_points` both require the member's signature on the
/// merchant's transaction, so proving they work at all needs a second key that
/// something here can sign with. Holding it is the whole reason the proof is
/// weaker than the product — see the banner `cosigned_banner` prints, which is
/// on every verb that uses this file.
///
/// **The precedent is deliberate and it is not new.** `customer_wallet.py` has
/// played the customer on six rails since this build's first month, bounded by
/// `customer_wallet.can_pay`; `handoff.md` describes it in exactly those terms.
/// This is that pattern reaching Ootle, and it carries the same boundary: a
/// dev bench proves a mechanism, and a merchant holding a customer's key is the
/// attack the mechanism exists to refuse.
///
/// Separate file rather than a second field in `StoredKey`, so that the
/// merchant's key file has exactly the shape it had before this landed and a
/// tool reading it cannot pick up a customer secret by accident.
/// Which dev-bench customer this invocation means, from `OOTLE_DEVBENCH_N`.
///
/// Defaults to 1, and 1 keeps the original filename so the key sealed on
/// 2026-08-14 — and the enrolment it holds on esmeralda — stays exactly where
/// it was. An env var rather than a positional argument because `enrol` and
/// `redeem` already have fixed argument positions and threading an optional
/// index through them would make the common case read worse.
///
/// **More than one exists because a measurement needed it.** The batching
/// record could establish that cost is linear in INSTRUCTIONS — 243 and 248 µT
/// for a second and third award — but the per-RECIPIENT increment rested on a
/// single comparison, because this workstation had exactly two accounts with
/// warm points vaults. Extrapolating a model from one data point is the thing
/// this repository refuses everywhere else.
/// The instant after which a payment must not be SUBMITTED, from
/// `OOTLE_PAY_DEADLINE_EPOCH`, or `None` when the caller named none.
///
/// THIS IS A SUBMISSION DEADLINE, NOT THE SALE'S EXPIRY. The caller subtracts
/// its safety margin before setting it, because a payment needs time to land:
/// given the raw expiry this would permit submitting with one second left,
/// which is exactly what the caller's margin exists to prevent. Two guards
/// enforcing different policies is worse than one, so the policy is decided
/// once, by the caller, and applied here.
///
/// ## Why this lives in the toolkit and not only in the caller
///
/// A cryptopos sale is time-boxed: the adapters credit a payment only when it
/// finalises at or before the sale's expiry, and a payment that lands one
/// second late is recorded as `needs-review` with `credited_native = 0` and
/// the full amount `sighted` -- money taken and attributed to nothing.
///
/// The Python callers check the window before they start, and that is not
/// enough. Everything between their check and `send_transaction` here is
/// network-capable work -- connecting, reading the epoch, preparing the
/// instructions, building and signing the request -- and all of it can take
/// longer than the margin they measured. Their last check is the last
/// PYTHON-side point at which nothing has been spent; it is not the last one.
///
/// So the deadline travels into the child and is read again immediately
/// before submission, which is genuinely the last instant at which nothing is
/// spent. What remains after that -- propagation and consensus finalisation --
/// is irreducible under the present component interface, because `pay` takes
/// an amount and a reference and no enforceable expiry.
///
/// It is an environment variable rather than an argument so that the callers'
/// argv stays a fixed, closed shape: `agent_wallet` builds argv from a table
/// precisely so that no caller can inject a verb, and adding a positional
/// would widen that surface for a value that is not a secret.
fn submission_deadline() -> Option<u64> {
    std::env::var("OOTLE_PAY_DEADLINE_EPOCH")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|epoch| *epoch > 0)
}

/// The refusal text for this instant, or `None` if submitting is still honest.
///
/// Pure, and separate from `refuse_if_window_closed` so that it can be tested
/// without setting a process-global environment variable -- Rust's test
/// harness runs in threads, and env-var tests interfere with each other.
fn window_refusal(deadline: Option<u64>, now: u64) -> Option<String> {
    let deadline = deadline?;
    if now < deadline {
        return None;
    }
    Some(format!(
        "REFUSING TO SUBMIT: the safe submission window closed {}s ago \
         (submission deadline {deadline}, now {now}); it is the sale's expiry \
         less the caller's margin. Preparation outlived it. Nothing was \
         submitted, so nothing was spent -- a payment landing now would very \
         likely be credited to no sale.",
        now.saturating_sub(deadline)
    ))
}

/// Refuse to submit if the sale's window has closed while we prepared.
fn refuse_if_window_closed() -> Result<(), Box<dyn std::error::Error>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match window_refusal(submission_deadline(), now) {
        Some(reason) => Err(reason.into()),
        None => Ok(()),
    }
}

fn devbench_n() -> u32 {
    std::env::var("OOTLE_DEVBENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

fn devbench_key_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME is not set");
    let n = devbench_n();
    let name = if n == 1 {
        "ootle_devbench_customer_key.json".to_string()
    } else {
        format!("ootle_devbench_customer_key_{n}.json")
    };
    PathBuf::from(home).join(".cryptopos_learning").join(name)
}

fn load_or_create_devbench_key() -> Result<OotleSecretKey, Box<dyn std::error::Error>> {
    load_or_create_key_at(devbench_key_path())
}

/// Where a **recovery** key lives, if it lives in a file at all.
///
/// Separate from `key_path()` because the entire value of the recovery key is
/// that it is not the till's key. A single file holding both would be the
/// thing `Loyalty::new` refuses, arrived at by a different door.
///
/// **A recovery key generated here is a FILE key, and that choice is
/// permanent.** `LedgerSigner` derives its key on the device from the device's
/// own seed; there is no import path from a file into it. Since the recovery
/// key is baked into the access rules and can never be rotated, generating one
/// here spends the hardware option forever. That is a fine answer for testnet
/// and a deliberate one for mainnet — it is not a default anybody should
/// arrive at by accident, which is why `key recovery` says so out loud and why
/// this comment exists next to the path rather than in a document.
fn recovery_key_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME is not set");
    PathBuf::from(home).join(".cryptopos_learning/ootle_recovery_key.json")
}

/// Turn an engine refusal into something the person holding the till can act on.
///
/// **Written after meeting one.** A retired operating key produces:
///
/// ```text
/// award OnlyFeeCommit(ExecutionFailure("At instruction #1: Encountered unknown
/// or out of scope signer badge with public key 2a29b127…"))
/// ```
///
/// The key in that message is the one the contract WANTED — the current
/// operating key — not the one that signed. So the merchant reads their own
/// failure and sees a public key they have never seen before, with nothing
/// saying "you were rotated out". That is the single most likely error on this
/// contract now, and the moment it happens is the moment somebody is either
/// recovering from a theft or is the thief.
///
/// Printed alongside the raw outcome, never instead of it. A translation that
/// hides the original is a translation nobody can check.
fn explain_failure(outcome: &str) {
    if outcome.contains("unknown or out of scope signer badge") {
        println!(
            "\n\
             ─────────────────────────────────────────────────────────────────────\n\
             THIS KEY IS NOT THE OPERATING KEY FOR THAT COMPONENT.\n\
             ─────────────────────────────────────────────────────────────────────\n\
             \n\
             The public key in the error above is the one the contract expects. It is\n\
             not the key that signed this call.\n\
             \n\
             Either this component was deployed by a different machine, or its operating\n\
             key has been ROTATED and this till is the one that was retired. Nothing was\n\
             charged beyond the fee, and nothing moved.\n\
             \n\
             If you rotated on purpose: use the machine holding the new key, or rotate\n\
             again to this one with `toolkit loyalty rotate <component>`.\n\
             \n\
             If you did NOT rotate: somebody holding the recovery key did. That key is\n\
             the only thing that can, and it is supposed to be in your safe."
        );
    }
}

/// Hex, because that is what `RistrettoPublicKeyBytes::from_str` parses and
/// therefore what `loyalty deploy` will accept back. A pretty format nobody
/// can paste into the next command is a worse format.
fn pubkey_hex(key: &RistrettoPublicKeyBytes) -> String {
    key.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Printed by every verb that signs with both keys.
///
/// `CHARTER.md` §2 — a ceiling ships on the surface that offers the feature.
/// The feature offered here is a co-signed transaction; the ceiling is that one
/// party holds both keys, so what is proven is the contract's path and not the
/// product's. On stderr so a harness capturing stdout still shows it to whoever
/// ran it.
fn cosigned_banner() {
    eprintln!(
        "DEV BENCH: this transaction is signed by the merchant key AND by a \
         customer key held on this same workstation.\n\
         It proves the contract's co-signature path executes. It does NOT show \
         a customer consenting —\n\
         nobody else holds a key here. Criteria 8 and 9 stay blocked; see \
         board/IN_PROGRESS.md R2a."
    );
}

// ───────────────────────────────────────────────────────────────────────────
// THE HANDOFF — R2, and what it is and is not
//
// `enrol` and `redeem` need two signatures on one transaction. Until now this
// binary produced both, from two key files sitting side by side, and said so in
// a banner on every run. That proves the CONTRACT'S path and nothing about a
// customer, because the party signing as the customer is the party signing as
// the merchant.
//
// The missing piece was never cryptography. `TransactionSignature::sign` takes
// a secret key, the SEALER's public key and the unsigned transaction — nothing
// else, no wallet, no daemon — and `UnsignedTransaction` derives minicbor
// unconditionally. So the three steps can happen in three processes that share
// no memory and no key file:
//
//   1. the merchant COMPOSES and writes a request      `--compose <path>`
//   2. the other party SIGNS it, holding only their own key   `sign-request`
//   3. the merchant ATTACHES, seals and submits             `submit-request`
//
// **THIS DOES NOT MOVE CRITERIA 8 AND 9.** A stranger's wallet is a product
// this project is not building (`board/IN_PROGRESS.md` K3). What this removes
// is the assumption that the two signatures must originate in one process —
// and with it the reason a real wallet could not be dropped into step 2 the
// day one exists. The interface is the deliverable; the customer is not.
//
// THE REQUEST IS NOT A SECRET AND IT IS NOT A CAPABILITY. It contains an
// unsigned transaction, the merchant's public key and the member's public key,
// all of which are public. Holding it lets nobody spend anything: without the
// member's secret key it cannot be signed, and without the merchant's it
// cannot be sealed. It is worth being precise about that, because a file
// passed hand to hand looks like a secret and this one is not.

/// One composed transaction, on its way to somebody else's key.
#[derive(serde::Serialize, serde::Deserialize)]
struct SigningRequest {
    /// What the customer is being asked to agree to, in words, so step 2 can
    /// show it. The device app displays a summary before returning a
    /// signature; this is the same idea with no device in it.
    summary: String,
    kind: String,
    network: String,
    /// The merchant's account public key. **Part of the signed message**, not
    /// decoration: a signature commits to its sealer, so one lifted onto a
    /// transaction sealed by somebody else does not verify.
    seal_signer: String,
    /// The public key whose signature this request needs. Step 2 refuses to
    /// sign with any other, because signing somebody else's request produces a
    /// signature that is valid, useless and confusing to find later.
    member_key: String,
    /// The canonical CBOR of the `UnsignedTransaction`, hex-encoded.
    ///
    /// CBOR rather than JSON because the signature commits to these exact
    /// bytes; a JSON round trip that re-ordered a map or widened an integer
    /// would hand step 3 a transaction that verifies differently from the one
    /// step 2 was shown.
    unsigned_cbor: String,
}

/// One signature, on its way back.
#[derive(serde::Serialize, serde::Deserialize)]
struct SigningResponse {
    member_key: String,
    signature_cbor: String,
}

/// Is this response the signature this request asked for? The decoded
/// signature if so, and a sentence a person can act on if not.
///
/// **THE CHECK THIS REPLACED COMPARED A LABEL, AND THE COST WAS NOT THE FEE.**
/// Found by review 2026-08-15. `SigningResponse::member_key` is a string that
/// step 2 writes into its own file, so asking it who signed and believing the
/// answer is asking the document to vouch for itself. Measured against the
/// code as it was: a response whose JSON named bench key `48d0…` while its
/// `signature_cbor` came from `2a29…` passed every check, and the binary
/// printed
///
/// ```text
/// signed by 48d0083832d082bb…
/// ```
///
/// which was false. The network refused the transaction at submission — HTTP
/// 400, `Invalid transaction signature`, before charging anything — so no fee
/// was lost and nothing wrong ever landed. What was lost is the only thing
/// this verb sells: it told the operator that a named customer had agreed to a
/// transaction, on the evidence of a field the transaction's own author wrote.
/// `CHARTER.md` §2 rule 1, and rule 4 — a guard is only worth what it audits,
/// and what this one has to audit is the signature.
///
/// Three questions, in the order that makes the error most useful:
///
///  1. does the response even claim to be the right key? (the label — kept,
///     because "you handed me the wrong file" is a better message than "this
///     does not verify")
///  2. **was it produced by that key?** (the signature's own embedded public
///     key, which no file author chooses)
///  3. **does it sign THIS transaction, sealed by THIS sealer?** (the same
///     Schnorr check the network performs, run before the submission instead
///     of after it — a signature lifted off a different request, or a request
///     tampered with after signing, stops here)
///
/// The network catches 2 and 3 too, which is why nothing was ever at risk of
/// landing wrongly. What it cannot do is stop this binary printing
/// `signed by <key>` on the way out — a sentence that has to be true when it
/// is printed, not eventually contradicted by a 400 nobody reads as "that was
/// not the customer".
fn check_signing_response(
    request: &SigningRequest,
    response: &SigningResponse,
    unsigned: &UnsignedTransaction,
) -> Result<TransactionSignature, String> {
    if response.member_key != request.member_key {
        return Err(format!(
            "this request needs a signature from {}\nand this signature is from \
             {}.\nNothing was submitted.",
            request.member_key, response.member_key
        ));
    }
    let signature: TransactionSignature =
        tari_bor::decode(&from_hex(&response.signature_cbor).map_err(|e| e.to_string())?)
            .map_err(|e| format!("the signature will not decode ({e})"))?;

    // WHO ACTUALLY SIGNED, asked of the signature rather than of the file that
    // carries it. `TransactionSignature` embeds the public key it was produced
    // with; the JSON beside it is a convenience for a reader and is not
    // evidence of anything.
    let signed_by = pubkey_hex(signature.public_key());
    if signed_by != request.member_key {
        return Err(format!(
            "the signature FILE says it is from {}\nbut the signature ITSELF was \
             produced by {signed_by},\nand this request needs {}.\nNothing was \
             submitted and no fee was paid.",
            response.member_key, request.member_key
        ));
    }

    let sealer: RistrettoPublicKeyBytes = request
        .seal_signer
        .parse()
        .map_err(|e| format!("the request's sealer is not a public key ({e:?})"))?;
    if !signature.verify_message(TransactionSignature::create_message(&sealer, unsigned)) {
        return Err(format!(
            "the signature does not verify against this transaction.\nIt was \
             produced by {signed_by}, but not over these bytes sealed by\n{} — so \
             either the request or the signature changed between\nthe two steps. \
             Nothing was submitted and no fee was paid.",
            request.seal_signer
        ));
    }
    Ok(signature)
}

/// Pull `--flag value` out of argv, returning the value and leaving the rest of
/// the positional arguments where every existing verb expects them.
///
/// Every verb in this binary reads its arguments by INDEX. A flag left in place
/// would shift every index after it, so the ones that take an optional trailing
/// argument would silently read the flag as that argument. Extracting first is
/// what keeps this addition from being a change to nine other verbs.
///
/// **A FLAG WITH NO VALUE IS AN ERROR, AND THE FIRST DRAFT RETURNED `None`.**
/// Found by review 2026-08-15, and the consequence was the exact defect
/// `--compose` was written to prevent. `toolkit loyalty enrol <c> <r> <v>
/// --compose` — the flag last, its filename forgotten — returned `None`, left
/// `--compose` sitting in argv, and so `composing` was false: the run fell
/// through to `load_or_create_devbench_key`, MINTED the counterparty's key on
/// a machine that had never held one, co-signed with it and submitted for a
/// fee. A guard whose precondition is lost to a missing argument is not a
/// guard. Refusing costs a typo one error message; the alternative cost a
/// permanent public record of the merchant signing as the customer.
fn take_flag(argv: &mut Vec<String>, name: &str) -> Result<Option<String>, String> {
    let Some(at) = argv.iter().position(|a| a == name) else {
        return Ok(None);
    };
    if at + 1 >= argv.len() {
        return Err(format!(
            "{name} needs a value and was given none. Nothing was read, \
             composed or submitted."
        ));
    }
    let value = argv.remove(at + 1);
    argv.remove(at);
    // AND ONLY ONCE. A second occurrence would be left in place by the removal
    // above and read as somebody else's positional argument, which is the
    // shape this whole function exists to prevent.
    if argv.iter().any(|a| a == name) {
        return Err(format!("{name} was given more than once, and which one \
                            was meant is not this binary's guess to make."));
    }
    Ok(Some(value))
}

fn load_or_create_key_at(path: PathBuf) -> Result<OotleSecretKey, Box<dyn std::error::Error>> {
    // `RistrettoSecretKey` is imported from where ootle-rs itself imports it
    // (`keys/secret.rs:9`), not from a guess at a re-export. `Hex` is a
    // tari_utilities trait and has to be in scope for `to_hex`/`from_hex` to
    // resolve at all — the error when it is missing names the method, not the
    // trait, which is why it is worth a line saying so.
    use tari_crypto::{ristretto::RistrettoSecretKey, tari_utilities::hex::Hex};

    if path.exists() {
        let raw = fs::read_to_string(&path)?;
        // SEALED FIRST, and the order matters: a sealed file has no
        // `account_secret` field, so trying the plaintext shape first would
        // report "will not parse" for a file that is perfectly well formed and
        // send its owner looking for corruption instead of for a passphrase.
        let stored: StoredKey = if let Ok(sealed) = serde_json::from_str::<SealedKey>(&raw) {
            let pass = passphrase(&format!("passphrase for {}", path.display()))?;
            unseal(&sealed, &pass)?
        } else {
            serde_json::from_str(&raw).map_err(|e| {
                format!(
                    "{} exists but will not parse ({e}). Refusing to overwrite it — \
                     it may be the only key holding this workstation's testnet \
                     funds. Move it aside by hand if you really do want a new account.",
                    path.display()
                )
            })?
        };
        // `HexError` does not implement `std::error::Error`, so `?` cannot
        // box it. Mapped by hand rather than papered over with a new error
        // type: a key file that parses as JSON but holds a bad hex string is
        // the same class of problem as one that will not parse at all, and it
        // deserves the same refusal rather than a cryptic conversion error.
        //
        // A closure rather than a nested `fn` since 2026-08-14: it has to name
        // the file it actually read, and there are two of those now. A nested
        // `fn` cannot capture, so the old one called `key_path()` — which would
        // have reported the merchant's path for a bad dev-bench file, sending
        // whoever hit it to edit the wrong key.
        let bad = |field: &'static str| {
            let shown = path.display().to_string();
            move |e: tari_crypto::tari_utilities::hex::HexError| {
                format!(
                    "{shown} parses as JSON but its `{field}` is not a valid key ({e}). \
                     Refusing to overwrite it — move it aside by hand if you \
                     really do want a new account."
                )
            }
        };
        let account = RistrettoSecretKey::from_hex(&stored.account_secret)
            .map_err(bad("account_secret"))?;
        let view = RistrettoSecretKey::from_hex(&stored.view_only_secret)
            .map_err(bad("view_only_secret"))?;
        return Ok(OotleSecretKey::new(NETWORK, account, view));
    }

    let secret = OotleSecretKey::random(NETWORK);
    let stored = StoredKey {
        account_secret: secret.account_secret().to_hex(),
        view_only_secret: secret.view_only_secret().to_hex(),
        network: NETWORK.to_string(),
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&path, serde_json::to_string_pretty(&stored)? + "\n")?;
    restrict(&path)?;
    eprintln!("created a new account key at {}", path.display());
    Ok(secret)
}

/// Owner-only permissions on the key file.
///
/// Unix-only, and deliberately not behind a portability shim: this repo runs
/// on Linux, and a `#[cfg]` that silently skipped the chmod elsewhere would be
/// a promise the file does not keep.
#[cfg(unix)]
fn restrict(path: &PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Print a committed transaction's receipt: what it created, and **which
/// epoch the executing validator thought it was in.**
///
/// That last field is why this function exists rather than being a debug
/// print. `TransactionReceipt::epoch` (`tari_engine_types-0.37.0/src/
/// transaction_receipt.rs:39`) is written by whoever executed the
/// transaction, from the same consensus state a template's
/// `Consensus::current_epoch()` reads. Comparing it against the indexer's
/// `/network` epoch at the same moment is a **second, independent** answer to
/// the question `epoch_probe` was built for — and it comes free with every
/// transaction this tool already submits, needing no template, no publish and
/// no fee beyond the one already paid.
///
/// It is not a substitute for the probe. This is the epoch the validator
/// stamped on a receipt; the probe is the epoch a template READS during
/// execution. They should be the same integer and nothing here proves it.
/// Two witnesses that agree are worth more than either alone, which is the
/// whole reason to print this rather than only the substates.
async fn report_receipt(
    pending: &ootle_rs::provider::PendingTransaction,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = pending.get_receipt().await?;
    println!("epoch   {} (as stamped by the executing validator)", receipt.epoch());
    for up in receipt.diff_summary().upped.iter() {
        println!("created {} v{}", up.substate_id, up.version);
    }
    // The logs are the only channel out of execution that survives this
    // client's path — `watch()` collapses a finalized result to `Commit` and
    // drops the `ExecuteResult` that held any return value. `epoch_probe`
    // emits its reading here on purpose, so the validator's stamped epoch
    // above and the template's own reading below sit on ONE document.
    // `logs` was REMOVED from TransactionReceipt in tari_engine_types 0.39.3 --
    // the struct carries `events` and no log field at all. Events are the only
    // channel out of execution that survives this client's path now, so the
    // probe template's own reading no longer appears here; the validator's
    // stamped epoch above still does.
    for event in receipt.events() {
        println!("event   {event:?}");
    }
    let fee = receipt.fee_receipt();
    println!("fee     {fee:?}");
    Ok(())
}

const USAGE: &str = "\
usage:
  toolkit account              show the address (offline, touches no network)
  toolkit faucet               take the fixed faucet amount
  toolkit publish <file.wasm>  publish a template, print its address and epoch
  toolkit epoch <template>     call EpochProbe::epoch_and_hash on a published template
  toolkit call <template> <fn> call a no-argument template FUNCTION (e.g. a constructor)
  toolkit payments deploy <template>
                                   stand up a PAYMENT component: it accepts XTR
                                   and every payment names the sale it is for,
                                   so two sales open at once cannot be confused.
  toolkit payments pay <component_...> <microTari> <sale-ref>
                                   pay a sale through the component, signed by
                                   THIS machine. Proves the binding against the
                                   real network; proves nothing about a stranger.
  toolkit payments pay ... --member <pubkey> --account <component_...>
                          --compose <request.json>
                                   THE CUSTOMER'S PAYMENT. Composes the same
                                   transaction withdrawing from the CUSTOMER's
                                   account and writes it out UNSIGNED, holding
                                   no customer key and creating none. They sign
                                   it on their own machine with `pocket`, and
                                   `submit-request` seals and submits it here.
                                   The summary in the file is what they read
                                   before agreeing, and a signature is consent
                                   to that sentence or to nothing.
  toolkit giftcard deploy <template> <per-card> <per-epoch>       stand up a component
  toolkit giftcard issue <component> <cents> <credit-resource>   mint into THIS account
  toolkit giftcard redeem <component> <cents> <credit-resource>  spend it back
  toolkit loyalty deploy <template> <rate> <per-issue> <per-epoch> <recovery-key>
                                   stand up a loyalty component. <rate> is
                                   points per cent and is PERMANENT - it has no
                                   setter and no tightening path. The two
                                   ceilings are in points and ratchet down only.
                                   <recovery-key> is a public key that gates
                                   rotation and both ratchets. It is PERMANENT,
                                   it is not this machine's key, and it must be
                                   held somewhere a stolen till cannot reach.
                                   The operating key is this toolkit's own and
                                   is the half that can be rotated later.
  toolkit loyalty award <component> <to-account> <points> <sale-ref> <points-resource>
                                   give points. The merchant's signature alone,
                                   because a point being GIVEN takes nothing
                                   from the customer.
  toolkit loyalty rotate <component> [<new-operating-key>]
                                   replace the operating key. Signed by the
                                   RECOVERY key, which is why a stolen till
                                   cannot do it. With no key it hands operation
                                   to THIS machine - the usual case, because you
                                   are standing at the replacement till. The old
                                   key stops working the moment this commits.
  toolkit key recovery             generate the recovery key, print its public
                                   key, and say plainly what choosing a file key
                                   costs. Never overwrites an existing one.
  toolkit key status [--devbench]  is the key file sealed or plaintext? (offline)
  toolkit key seal   [--devbench]  encrypt it with a passphrase (offline).
                                   Protects a stolen machine, disk or backup.
                                   Does NOT protect a running till - the key is
                                   plaintext in memory to sign, and
                                   OOTLE_KEY_PASSPHRASE is readable by any
                                   process running as you.
  toolkit loyalty award-batch <component> <points-resource> <account>:<points>:<ref> ...
                                   N awards in ONE transaction. An award is ~90%
                                   fixed cost per transaction, so each extra one
                                   costs 358 uT against 3,493 standalone. A
                                   transaction is ATOMIC - one unreadable
                                   account fails the whole batch.
  toolkit open-account <otl_esm_...> [amount=1]
                                   OPEN A STRANGER'S ACCOUNT, merchant paying.
                                   A fresh wallet's account substate does not
                                   exist until somebody creates it, and a
                                   customer who has never held XTR cannot pay
                                   for one - so nothing can be awarded to them.
                                   A transfer of any positive amount creates it
                                   as a side effect. The amount is not a
                                   balance; existence is what is being bought.
                                   Harmless to run twice.
  toolkit devbench account         the DEV BENCH customer's address (offline)
  toolkit devbench faucet          fund the DEV BENCH customer's account
  toolkit devbench pay-sale <component_...> <microTari> <sale-ref>
                                   the customer pays a PAYMENT COMPONENT, naming
                                   the sale. Unlike `pay` below, the money says
                                   which sale it settles, so two sales open at
                                   once cannot be confused for one another.
  toolkit devbench pay <otl_esm_...> <microTari>
                                   the customer pays the merchant. The one
                                   direction no other verb sends, and what a
                                   payment rail needs. Signed by the dev bench
                                   key on this workstation, so it proves the
                                   rail settles a real deposit -- not that a
                                   stranger paid.
  toolkit loyalty enrol <component> <points-resource> <points-vault>
  toolkit loyalty redeem <component> <points-resource> <points> <sale-ref> <enrolments-resource>
                                   redeem wants the enrolments resource too:
                                   it reads the enrolment NFT out of the
                                   register rather than taking it as an
                                   argument, so the transaction must declare
                                   that substate as an input by id.
                                   BOTH KEYS ARE HELD HERE. These two need the
                                   customer's signature as well as the
                                   merchant's, so they sign with the dev-bench
                                   customer key and prove the contract's
                                   co-signature path executes. That is not a
                                   customer consenting and it is not evidence
                                   for criteria 8 and 9 - board/IN_PROGRESS.md
                                   R2a says what it is and is not.
  toolkit loyalty enrol|redeem ... --member <pubkey> --account <component>
                                   --compose <request.json>
                                   THE HANDOFF. Compose the transaction and
                                   write it out WITHOUT signing it, holding no
                                   customer key and creating none. --member and
                                   --account say who the customer is; both are
                                   public and go together.
  toolkit sign-request <request.json> [<signature.json>]
                                   Sign somebody else's composed transaction
                                   with the key on THIS machine. Offline: no
                                   indexer, no fee, nothing submitted. Refuses
                                   any request that does not name this key.
                                   This is the step a customer's wallet would
                                   perform.
  toolkit submit-request <request.json> <signature.json>
                                   Attach the signature, seal with this
                                   machine's key, submit. Refuses a signature
                                   from the wrong key and a request composed to
                                   be sealed by a different machine - both for
                                   free, where the engine would charge a fee to
                                   say the same thing.
                                   A SIGNATURE FROM A FILE PROVES CONSENT BY
                                   THE HOLDER OF A KEY, and not that the holder
                                   is a customer rather than the merchant with
                                   two key files. Criteria 8 and 9 move when a
                                   wallet somebody else controls signs.
  toolkit warranty deploy <template> <per-epoch>
                                   stand up a warranty component. <per-epoch>
                                   is registrations per epoch and ratchets down
                                   only. There is no per-issue ceiling because
                                   `register` mints exactly one.
  toolkit membership deploy <template> <per-epoch>
                                   stand up a membership component. <per-epoch>
                                   is grants per epoch and ratchets down only.
  toolkit finality <component> <credit-resource> [n=5] [cents=100]
                                   time N issue+redeem pairs on esmeralda and
                                   report TWO numbers: what a customer waits
                                   (free phase) and the cycle length (locked).
                                   Writes harnesses/measurements/<date>-ootle-finality.json,
                                   never over an existing one.";

/// One timed submit→watch observation.
///
/// `submit_ms` is the round trip of `send_transaction` (indexer accepts the
/// payload). `finality_ms` is the wait inside `watch()` until the indexer
/// reports a terminal outcome (commit / fee-only / reject) or the client
/// timeout fires. That second number is the open question in
/// `OOTLE_SCOPE.md` §3; the first is transport, not consensus.
///
/// `phase` IS LOAD-BEARING, and the first run of this command shipped without
/// it. Ootle commits on a cadence, not on demand. A transaction submitted the
/// instant the previous one committed is phase-locked to that cadence and
/// therefore waits a FULL cycle — so a back-to-back stream measures the cycle
/// length and calls it latency. The 2026-07-31 evidence: twelve consecutive
/// locked samples spanned 724 ms (58.2-58.9 s) while the only two free-phase
/// samples in the same dataset came back in 35.3 s and 52.0 s. Both numbers
/// are real and they answer different questions, so each sample now records
/// which one it is:
///
///   "free"   — submitted at an arbitrary point in the cycle. This is what a
///              customer's sale sees, because a customer does not wait for
///              the previous block to land before deciding to pay.
///   "locked" — submitted immediately after a commit. This is the cycle
///              length, i.e. the WORST case and the back-to-back throughput.
#[derive(serde::Serialize)]
struct FinalitySample {
    run: u32,
    action: &'static str,
    phase: &'static str,
    /// How long this sample deliberately waited before submitting, to break
    /// the phase lock. Zero for the locked samples, which is the point.
    stagger_ms: u64,
    cents: u64,
    tx_id: Option<String>,
    outcome: String,
    committed: bool,
    timed_out: bool,
    submit_ms: u64,
    finality_ms: u64,
    total_ms: u64,
    /// JSON key keeps the µT unit capitalisation used by every other
    /// ootle-fees / epoch-identity measurement in this repo.
    #[serde(rename = "fees_paid_uT")]
    fees_paid_ut: Option<u64>,
    epoch: Option<u64>,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct FinalitySummary {
    group: String,
    n_committed: usize,
    n_failed: usize,
    finality_ms_min: Option<u64>,
    finality_ms_median: Option<u64>,
    finality_ms_max: Option<u64>,
    finality_ms_mean: Option<f64>,
    total_ms_median: Option<u64>,
}

fn median_u64(sorted: &[u64]) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let mid = sorted.len() / 2;
    Some(if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        // Integer average of the two middle values; for even N this is the
        // conventional lower-biased median for integers and avoids float until
        // the mean, which is reported separately.
        (sorted[mid - 1] + sorted[mid]) / 2
    })
}

/// Summarise the subset of `samples` that `keep` selects.
///
/// Takes a predicate rather than an action name so the same arithmetic serves
/// both cuts of the data: by action (issue vs redeem, which is who pays) and
/// by phase (free vs locked, which is what the number MEANS). Medians are
/// over committed samples only — a timeout contributes the client budget, not
/// a finality, and averaging the two would invent a number describing neither.
fn summarise(
    group: &str,
    samples: &[FinalitySample],
    keep: impl Fn(&FinalitySample) -> bool,
) -> FinalitySummary {
    let of_group: Vec<&FinalitySample> = samples.iter().filter(|s| keep(s)).collect();
    let committed: Vec<&FinalitySample> = of_group.iter().copied().filter(|s| s.committed).collect();
    let mut finals: Vec<u64> = committed.iter().map(|s| s.finality_ms).collect();
    let mut totals: Vec<u64> = committed.iter().map(|s| s.total_ms).collect();
    finals.sort_unstable();
    totals.sort_unstable();
    let mean = if finals.is_empty() {
        None
    } else {
        Some(finals.iter().sum::<u64>() as f64 / finals.len() as f64)
    };
    FinalitySummary {
        group: group.to_string(),
        n_committed: committed.len(),
        n_failed: of_group.len() - committed.len(),
        finality_ms_min: finals.first().copied(),
        finality_ms_median: median_u64(&finals),
        finality_ms_max: finals.last().copied(),
        finality_ms_mean: mean,
        total_ms_median: median_u64(&totals),
    }
}

/// Default measurements path: next to the other live probes, not beside the
/// binary. Resolved from this crate's source tree so a release binary run
/// from anywhere still lands the file where the harnesses expect it.
///
/// NEVER RETURNS A PATH THAT ALREADY EXISTS. `measurements/` is dated rather
/// than overwritten so that drift stays visible — that is the whole reason
/// those files are committed — but a date is only unique once per day, and
/// the first version of this command silently destroyed the morning's run
/// when it was re-run in the afternoon. (Measured: it destroyed the 5-pair
/// record on 2026-07-31 and only a backup taken beforehand got it back.)
/// A second run on the same day gets `-2`, a third `-3`.
///
/// The caller resolves this BEFORE submitting anything, because the failure
/// this prevents is worst at the end: testnet XTR spent, samples collected,
/// and then a write that lands on top of data nobody can re-measure.
fn finality_out_path() -> PathBuf {
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../harnesses/measurements");
    let first = dir.join(format!("{date}-ootle-finality.json"));
    if !first.exists() {
        return first;
    }
    // Bounded so a bug cannot spin: 99 runs in one day is not a scenario, it
    // is a symptom, and erroring out is better than looping forever.
    for n in 2..100 {
        let candidate = dir.join(format!("{date}-ootle-finality-{n}.json"));
        if !candidate.exists() {
            return candidate;
        }
    }
    first
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut argv: Vec<String> = std::env::args().collect();
    // BEFORE ANYTHING READS AN INDEX. See `take_flag`: every verb here parses
    // positionally, so a flag left in the vector would be read as somebody
    // else's optional argument.
    let compose_to = take_flag(&mut argv, "--compose")?;
    let member_flag = take_flag(&mut argv, "--member")?;
    let account_flag = take_flag(&mut argv, "--account")?;
    let argv = argv;
    let command = argv.get(1).map(String::as_str).unwrap_or("help");
    if !matches!(
        command,
        "account"
            | "key"
            | "devbench"
            | "faucet"
            | "publish"
            | "epoch"
            | "call"
            | "giftcard"
            | "loyalty"
            | "payments"
            | "warranty"
            | "membership"
            | "finality"
            | "sign-request"
            | "submit-request"
            | "open-account"
    ) {
        eprintln!("{USAGE}");
        return Ok(());
    }

    // KEY CUSTODY, and offline before anything else so it works on a machine
    // with no network and — more to the point — so `seal` never has to build a
    // provider, which would mean unsealing the key it is about to seal.
    // STEP 2 OF THE HANDOFF, AND IT IS OFFLINE — before any provider is built,
    // for the same reason `key seal` is. This is the step a customer's own
    // device performs, and a step that needed an indexer would be one a wallet
    // could not take on a phone in a shop with no signal. It reads a file,
    // holds exactly one key, and writes a file.
    if command == "sign-request" {
        use tari_crypto::ristretto::RistrettoSecretKey;
        use tari_ootle_transaction::{TransactionSignature, UnsignedTransaction};

        let path = argv.get(2).ok_or(
            "sign-request needs the path to a request file written by \
             `--compose`.\nOptionally a second path to write the signature to; \
             otherwise it goes to stdout.",
        )?;
        let request: SigningRequest = serde_json::from_str(&fs::read_to_string(path)?)
            .map_err(|e| format!("{path} is not a signing request ({e})"))?;
        if request.network != format!("{NETWORK:?}").to_lowercase()
            && request.network != format!("{NETWORK:?}")
        {
            return Err(format!(
                "this request is for {}, and this binary only ever speaks to {NETWORK:?}",
                request.network
            )
            .into());
        }

        // WHOSE SIGNATURE IS BEING ASKED FOR. The customer key here is the dev
        // bench's, selected by OOTLE_DEVBENCH_N — in a real deployment this
        // whole verb is what a wallet does instead. Either way it must be the
        // key the request names: a signature from any other key is valid,
        // useless, and discovered three steps later when the engine rejects
        // the transaction for a missing signer.
        let secret = load_or_create_devbench_key()?;
        let address = secret.to_address();
        let mine = pubkey_hex(address.account_public_key());
        if mine != request.member_key {
            return Err(format!(
                "this request wants a signature from {}\nand the key loaded here is {mine}.\n\
                 Signing it anyway would produce a signature that is valid and \
                 attached to nothing.\nOOTLE_DEVBENCH_N selects which bench key \
                 is loaded.",
                request.member_key
            )
            .into());
        }

        // WHAT IS BEING AGREED TO, SHOWN BEFORE IT IS SIGNED. The Ledger app
        // recomputes the message and displays a summary for approval; with no
        // device in the path, printing it is the same promise kept by weaker
        // means, and saying which is which is `CHARTER.md` §2 rule 6.
        eprintln!("SIGNING, and nothing here can check that the summary matches the bytes:");
        eprintln!("  {}", request.summary);
        eprintln!("  sealed by  {}", request.seal_signer);
        eprintln!("  signing as {mine}");

        let unsigned: UnsignedTransaction =
            tari_bor::decode(&from_hex(&request.unsigned_cbor).map_err(|e| e.to_string())?)
                .map_err(|e| format!("the request's transaction will not decode ({e})"))?;
        let seal_signer: RistrettoPublicKeyBytes = request
            .seal_signer
            .parse()
            .map_err(|e| format!("the request's sealer is not a public key ({e:?})"))?;
        let secret_key: RistrettoSecretKey = secret.account_secret().clone();
        let signature = TransactionSignature::sign(&secret_key, &seal_signer, &unsigned);

        let response = SigningResponse {
            member_key: mine,
            signature_cbor: to_hex(&tari_bor::encode(&signature)?),
        };
        let body = serde_json::to_string_pretty(&response)?;
        match argv.get(3) {
            Some(out) => {
                fs::write(out, format!("{body}\n"))?;
                eprintln!("\nwrote {out}");
            }
            None => println!("{body}"),
        }
        return Ok(());
    }

    if command == "key" {
        let verb = argv.get(2).map(String::as_str).unwrap_or("");

        // BEFORE THE READ BELOW, because this is the one key verb whose job is
        // to create a file rather than inspect one.
        if verb == "recovery" {
            let path = recovery_key_path();
            let existed = path.exists();
            // Reuses `load_or_create_key_at`, so an existing file is opened and
            // never overwritten — the refusal that protects the merchant's key
            // protects this one for a much larger reason. A recovery key that
            // got regenerated would not "reset" anything: the OLD public key is
            // in the access rules of a live component, permanently, and the new
            // file would simply be a key that authorises nothing.
            let secret = load_or_create_key_at(path.clone())?;
            let address = secret.to_address();
            let pk = pubkey_hex(address.account_public_key());

            println!("file    {}", path.display());
            println!("state   {}", if existed { "already existed - NOT regenerated" } else { "created" });
            println!("public  {pk}");
            println!("\npaste that public key as the last argument to `loyalty deploy`.");

            if existed {
                println!(
                    "\nThis file was already here. It was opened, not replaced. If a component \
                     was\ndeployed against this key, that pairing is permanent — regenerating \
                     would not\nreset anything, it would just leave you holding a key that \
                     authorises nothing."
                );
            } else {
                println!(
                    "\n\
                     ─────────────────────────────────────────────────────────────────────\n\
                     THIS IS A FILE KEY ON THIS MACHINE, AND THAT IS PERMANENT.\n\
                     ─────────────────────────────────────────────────────────────────────\n\
                     \n\
                     The recovery key gates rotation and both ceiling ratchets. It is baked\n\
                     into the component's access rules at deploy and can NEVER be changed.\n\
                     \n\
                     A hardware device derives its key on the device, from the device's own\n\
                     seed. There is no way to move this file onto one. So deploying against\n\
                     this key chooses a file key forever.\n\
                     \n\
                     For testnet that is the right answer and you are done.\n\
                     \n\
                     For anything real, either use a device instead — read its public key and\n\
                     pass that to `loyalty deploy` — or move THIS file off this machine after\n\
                     deploying, and back it up. A recovery key sitting next to the till key it\n\
                     is supposed to outrank protects nothing: whoever steals the machine gets\n\
                     both, and the pair is exactly the shape the contract refuses at birth.\n\
                     \n\
                     What you lose if you lose it: every future rotation, and the ability to\n\
                     tighten a ceiling ever again. The programme keeps running on whatever\n\
                     operating key is current. It just cannot be recovered from again."
                );
            }
            return Ok(());
        }

        let which = if argv.get(3).map(String::as_str) == Some("--devbench") {
            devbench_key_path()
        } else {
            key_path()
        };
        let raw = fs::read_to_string(&which)
            .map_err(|e| format!("{} cannot be read ({e})", which.display()))?;
        let already = serde_json::from_str::<SealedKey>(&raw).is_ok();
        match verb {
            "status" => {
                println!("file    {}", which.display());
                println!("state   {}", if already { "sealed" } else { "PLAINTEXT" });
                if !already {
                    println!(
                        "\nA plaintext key file is the whole merchant account. Anyone who \
                         takes this\nmachine, its disk or a backup of it can trade as the \
                         merchant until the key is\nrotated — which since 2026-08-14 is \
                         possible: `loyalty rotate` replaces it,\nsigned by the recovery key. \
                         Bounded and survivable, not permanent.\n\n`toolkit key seal` narrows \
                         the window; read what it does NOT protect against\nfirst."
                    );
                }
            }
            "seal" => {
                if already {
                    // Re-sealing would need the old passphrase to open it and
                    // would gain nothing. Refusing beats a second prompt whose
                    // failure mode is a file encrypted twice under keys nobody
                    // recorded.
                    return Err(format!("{} is already sealed.", which.display()).into());
                }
                let stored: StoredKey = serde_json::from_str(&raw).map_err(|e| {
                    format!("{} will not parse ({e}). Refusing to touch it.", which.display())
                })?;
                let pass = passphrase("new passphrase")?;
                if pass.len() < 8 {
                    return Err("a passphrase under eight characters is not one. \
                                Nothing was changed."
                        .into());
                }
                let again = passphrase("again")?;
                if pass != again {
                    return Err("those do not match. Nothing was changed.".into());
                }
                let sealed = seal(&stored, &pass)?;
                // WRITE BESIDE, THEN RENAME. A crash between truncate and write
                // on the plaintext path would destroy an unrecoverable account,
                // and this is the one file in the repository where that is
                // fatal rather than annoying.
                let tmp = which.with_extension("sealing");
                fs::write(&tmp, serde_json::to_string_pretty(&sealed)? + "\n")?;
                restrict(&tmp)?;
                // Proves the new file opens BEFORE the plaintext one stops
                // existing. Sealing a key you cannot then unseal is the only
                // outcome here worse than leaving it in plaintext.
                let check = fs::read_to_string(&tmp)?;
                let parsed: SealedKey = serde_json::from_str(&check)?;
                let opened = unseal(&parsed, &pass)?;
                if opened.account_secret != stored.account_secret
                    || opened.view_only_secret != stored.view_only_secret
                {
                    fs::remove_file(&tmp).ok();
                    return Err("the sealed file did not decrypt back to the same key. \
                                Nothing was changed."
                        .into());
                }
                fs::rename(&tmp, &which)?;
                println!("sealed  {}", which.display());
                println!(
                    "\nVerified: it decrypts back to the same account before the plaintext \
                     was replaced.\nSet OOTLE_KEY_PASSPHRASE for unattended use — and read \
                     `SealedKey`'s docs on what\nthat costs, because it is readable by any \
                     process running as you."
                );
            }
            _ => return Err("key verb must be `status` or `seal`".into()),
        }
        return Ok(());
    }

    let secret = load_or_create_key()?;
    let address = secret.to_address();

    // OFFLINE FIRST, and separated from every other command on purpose. This
    // is the one thing that still works when the indexer is down, and it is
    // what you paste into a faucet web page if this tool's own faucet call
    // ever stops working.
    if command == "account" {
        println!("network  {NETWORK}");
        println!("address  {address}");
        // THE ACCOUNT COMPONENT, printed because `loyalty award` demands one
        // and this verb was the obvious place to look for it and did not have
        // it. An Ootle ADDRESS and the ACCOUNT COMPONENT it owns are
        // different things - see the `ToAccountAddress` note at the imports -
        // and `award <component> <to> ...` wants the second. Derived offline,
        // like everything else here: it is a function of the key, so it
        // answers while the indexer is down.
        println!("account  {}", address.to_account_address());
        // THE HEX PUBLIC KEY, because two verbs demand one and until
        // 2026-08-14 nothing printed one. `loyalty deploy` wants a recovery
        // key and `loyalty rotate` wants a new operating key, both in this
        // format; an operator with two machines had no way to get the other
        // one's key out of this tool. A flag that is required and unobtainable
        // is not a guard, it is a wall.
        println!("pubkey   {}", pubkey_hex(address.account_public_key()));
        println!("key file {}", key_path().display());
        return Ok(());
    }

    // The dev bench's own identity, and offline for the same reason `account`
    // is: the harness needs the account component address before there is
    // anything on the network to read it from.
    let devbench_verb = argv.get(2).map(String::as_str).unwrap_or("");
    if command == "devbench" && devbench_verb == "account" {
        let customer = load_or_create_devbench_key()?;
        let customer_address = customer.to_address();
        println!("network  {NETWORK}");
        println!("address  {customer_address}");
        println!("account  {}", customer_address.to_account_address());
        println!("pubkey   {}", pubkey_hex(customer_address.account_public_key()));
        println!("key file {}", devbench_key_path().display());
        eprintln!(
            "DEV BENCH: a customer key held on the merchant's workstation. Not \
             a customer."
        );
        return Ok(());
    }

    // WHICH KEYS THIS INVOCATION HOLDS, decided before the wallet is built
    // because the answer differs by verb and getting it wrong is a fee.
    //
    //   * `devbench faucet` funds the CUSTOMER's account, so the customer must
    //     be the default signer — the default is who seals, and therefore who
    //     pays and whose account `take_faucet_funds` creates.
    //   * `loyalty enrol` / `loyalty redeem` are co-signed: the MERCHANT stays
    //     default, because the merchant is the party the contract's access rule
    //     gates on and sealing is what carries that badge. The customer is
    //     registered as an additional signer, which is what lets
    //     `authorize_transaction` produce their signature over the merchant's
    //     composed transaction. That asymmetry is the whole shape of the
    //     feature: the merchant composes and seals, the customer only consents.
    //   * Everything else holds the merchant's key alone, exactly as before.
    let loyalty_verb = argv.get(2).map(String::as_str).unwrap_or("");
    let cosigned = command == "loyalty" && matches!(loyalty_verb, "enrol" | "redeem");
    let devbench_signs = command == "devbench";
    //   * `loyalty rotate` is the one verb this machine's key CANNOT sign. It
    //     is gated on the recovery key by an engine rule, deliberately out of
    //     reach of the key it replaces — a thief holding the till would
    //     otherwise rotate the merchant out and own the remedy.
    let recovery_signs = command == "loyalty" && loyalty_verb == "rotate";

    let signer = PrivateKeyProvider::new(secret);
    let mut wallet = OotleWallet::from(signer);
    let mut customer_address = None;
    let mut recovery_address = None;
    if recovery_signs {
        let path = recovery_key_path();
        if !path.exists() {
            return Err(format!(
                "rotation is signed by the RECOVERY key and {} does not exist.\n\
                 If the recovery key for this component is on a device, this verb cannot \
                 drive it yet.\nIf it is a file, put it back at that path — it is the only \
                 thing that can rotate\nthis component, and nothing else can be substituted \
                 for it.",
                path.display()
            )
            .into());
        }
        let recovery = load_or_create_key_at(path)?;
        let addr = recovery.to_address();
        wallet.register_key_provider(PrivateKeyProvider::new(recovery));
        // REGISTERED, NOT MADE THE DEFAULT SIGNER — and the difference is the
        // whole operational story of the recovery key.
        //
        // The default signer seals the transaction and therefore pays the fee,
        // which means having a funded account on-chain. Discovered by trying
        // it: the first live rotation failed with "Component does not exist",
        // because a key that has only ever sat in a safe has no account for a
        // fee to come out of. A merchant would have met that error mid-theft,
        // which is the worst moment to learn that the recovery key cannot pay
        // for its own rotation.
        //
        // So the till composes and pays, and the recovery key only authorises.
        // That is the same shape `enrol` and `redeem` already use for the
        // customer, and it is the shape a hardware device supports directly —
        // `LedgerSigner::sign_authorization` is `SignMode::AddSigner`. The key
        // in the safe stays a bare key: no account, no funds, no maintenance.
        recovery_address = Some(addr);
    }
    // COMPOSE MODE HOLDS NO CUSTOMER KEY, WHICH IS THE ENTIRE POINT. Without
    // this branch `load_or_create_devbench_key` would run — and its name is
    // exact: on a merchant machine that has never had one, it would CREATE a
    // customer key and cheerfully sign with it. A handoff whose first step
    // mints the other party's key is not a handoff.
    let composing = compose_to.is_some();
    if (cosigned || devbench_signs) && !composing {
        let customer = load_or_create_devbench_key()?;
        let addr = customer.to_address();
        wallet.register_key_provider(PrivateKeyProvider::new(customer));
        if devbench_signs {
            wallet.set_default_signer(&addr)?;
        }
        customer_address = Some(addr);
    }
    let wallet = wallet;
    // Finality is the command that CARES about the timeout value: every other
    // verb inherits the same 120 s budget so a slow testnet day does not
    // masquerade as a tool bug. The skill's default of 32 s is still the
    // library default; this connection overrides it.
    let mut provider = ProviderBuilder::new()
        .with_network(NETWORK)
        .wallet(wallet)
        .connect_with_transaction_timeout(ootle_rs::default_indexer_url(NETWORK), TX_TIMEOUT)
        .await?;

    // Read once, here, so every verb below stamps the same bound rather than
    // each asking again and drifting apart across a slow command.
    let max_epoch = Epoch(
        provider
            .get_epoch()
            .await?
            .as_u64()
            .checked_add(MAX_EPOCH_WINDOW)
            .ok_or("epoch counter overflowed")?,
    );

    match command {
        // STEP 3 OF THE HANDOFF. The merchant is back, holding a request it
        // composed and a signature somebody else produced. It attaches, seals
        // with its own key and submits — the only step that needs a network,
        // a fee, or this machine's key.
        "submit-request" => {
            let request_path = argv
                .get(2)
                .ok_or("submit-request needs the request file, then the signature file")?;
            let signature_path = argv.get(3).ok_or("and the signature file")?;
            let request: SigningRequest =
                serde_json::from_str(&fs::read_to_string(request_path)?)
                    .map_err(|e| format!("{request_path} is not a signing request ({e})"))?;
            let response: SigningResponse =
                serde_json::from_str(&fs::read_to_string(signature_path)?)
                    .map_err(|e| format!("{signature_path} is not a signature ({e})"))?;

            // AND THE SEALER HAS TO BE THIS MACHINE. A request composed by a
            // different till would produce a transaction sealed by the wrong
            // key, and the customer's signature commits to the sealer — so it
            // would fail on the network for a reason nobody would think to
            // look for here. Checked here rather than inside
            // `check_signing_response` because it is the one question that
            // depends on which machine is running, and that function is
            // deliberately about the two files alone.
            let mine = pubkey_hex(address.account_public_key());
            if request.seal_signer != mine {
                return Err(format!(
                    "this request was composed to be sealed by {}\nand this machine's \
                     key is {mine}.\nThe signature commits to the sealer, so submitting \
                     it here would fail on the network.",
                    request.seal_signer
                )
                .into());
            }

            let unsigned: UnsignedTransaction = tari_bor::decode(
                &from_hex(&request.unsigned_cbor).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("the request's transaction will not decode ({e})"))?;
            let signature = check_signing_response(&request, &response, &unsigned)?;

            println!("submitting {}", request.kind);
            println!("  {}", request.summary);
            println!("  signed by {}", response.member_key);
            eprintln!(
                "THE SIGNATURE CAME FROM A FILE, and this binary cannot tell whose \
                 machine produced it.\nWhat it proves is that the holder of {} agreed \
                 to THIS transaction — not that\nthey are a customer rather than the \
                 merchant with two key files. Criteria 8 and 9 in\nboard/IN_PROGRESS.md \
                 move when a wallet somebody else controls signs, and not before.",
                response.member_key
            );

            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .add_authorization(signature.into())
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("submit  {outcome:?}");
            explain_failure(&format!("{outcome:?}"));
            println!("tx      {tx_id}");
            report_receipt(&pending).await?;
        }

        // Same call as `faucet`, with the dev bench's key as the default
        // signer. It gets its own verb rather than a flag on `faucet` because
        // the two fund different accounts, and a flag that silently changes
        // whose money moves is the kind of surface this repository refuses.
        "devbench" => {
            if devbench_verb != "faucet" && devbench_verb != "pay" && devbench_verb != "pay-sale" {
                return Err(
                    "devbench verb must be `account`, `faucet`, `pay` or `pay-sale`".into(),
                );
            }
            let customer_address = customer_address
                .as_ref()
                .expect("registered above whenever command == devbench");

            // THE CUSTOMER PAYING THE MERCHANT, which is the one direction no
            // other verb here can send. `open-account` moves merchant ->
            // stranger and `faucet` fills whoever signs; a payment rail needs
            // stranger -> merchant, for an amount the invoice chose rather than
            // a fixed faucet grant. `pocket` cannot do it: it is offline by
            // design and signs without submitting.
            //
            // It sits under `devbench` for the reason the comment above gives
            // for `devbench faucet` -- the signer is the dev bench's key, held
            // on this workstation, so this DOES NOT prove a stranger paid. It
            // proves the rail observes and settles a real deposit that this
            // machine did not make from the merchant's own account.
            if devbench_verb == "pay" {
                use ootle_rs::template_types::constants::TARI_TOKEN;

                let target = argv.get(3).ok_or(
                    "devbench pay needs the merchant's address (the `otl_esm_...` \
                     string, not a component) and then an amount in microTari",
                )?;
                let target: ootle_rs::Address = target.parse().map_err(|e| {
                    format!("{target} is not an Ootle address ({e:?}); it should begin `otl_esm_`")
                })?;
                let amount: u64 = argv
                    .get(4)
                    .ok_or("devbench pay needs an amount in microTari")?
                    .parse()
                    .map_err(|e| format!("the amount must be a whole number of microTari ({e})"))?;
                if amount == 0 {
                    return Err("a zero payment settles nothing".into());
                }
                let unsigned = IAccount::new(&provider, max_epoch)
                    .pay_fee(CALL_FEE)
                    .public_transfer(&target, TARI_TOKEN, Amount::new(amount as u128))
                    .prepare()
                    .await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await?;
                refuse_if_window_closed()?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("from    {customer_address}");
                println!("to      {target}");
                println!("amount  {amount} uT");
                println!("pay     {outcome:?}");
                println!("tx      {tx_id}");
                explain_failure(&format!("{outcome:?}"));
                return Ok(());
            }

            // PAYING A SALE, not an address. `pay` above sends XTR to the
            // merchant's account, where nothing about the transfer says which
            // sale it settles -- D48 measured what that costs: the running
            // total decides, so a payment made for one sale settles whichever
            // other sale polls first. This calls the payment component's `pay`
            // method with the sale reference as an ARGUMENT, which is the whole
            // of the per-sale binding.
            //
            // Still the dev bench's key, so this still does not prove a
            // stranger paid. What it proves is that the component's binding
            // works against a real network.
            if devbench_verb == "pay-sale" {
                use ootle_rs::template_types::constants::TARI_TOKEN;

                let component = argv.get(3).ok_or(
                    "devbench pay-sale needs the payment component address, then an amount \
                     in microTari, then the sale reference",
                )?;
                let component: ComponentAddress = component
                    .strip_prefix("component_")
                    .unwrap_or(component)
                    .parse()
                    .map_err(|e| format!("{component} is not a component address ({e:?})"))?;
                let amount: u64 = argv
                    .get(4)
                    .ok_or("devbench pay-sale needs an amount in microTari")?
                    .parse()
                    .map_err(|e| format!("the amount must be a whole number of microTari ({e})"))?;
                if amount == 0 {
                    return Err("a zero payment settles nothing".into());
                }
                let sale_ref = argv
                    .get(5)
                    .ok_or("devbench pay-sale needs the sale reference the invoice printed")?
                    .clone();
                if sale_ref.is_empty() {
                    return Err("a payment must name the sale it is for".into());
                }

                let me = customer_address.to_account_address();
                // DECLARE THE PAYER'S OWN VAULT AS AN INPUT. `call_method`
                // auto-adds the vaults of the component being CALLED, but the
                // withdraw below goes through `.then()` on the raw builder,
                // which adds no wants at all -- so the customer's vault has to
                // be asked for by hand or instruction #1 fails SubstateNotFound.
                // The giftcard redeem path records having learned this the
                // expensive way.
                let unsigned = IComponent::new(&provider, max_epoch)
                    .want_vault_for(me, TARI_TOKEN, true)
                    .then(|b| {
                        b.call_method(
                            me,
                            "withdraw",
                            args![TARI_TOKEN, Amount::new(amount as u128)],
                        )
                        .put_last_instruction_output_on_workspace("payment")
                    })
                    .call_method(component, "pay", args![Workspace("payment"), sale_ref.clone()])
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await?;
                refuse_if_window_closed()?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("from    {customer_address}");
                println!("to      {component}");
                println!("amount  {amount} uT");
                println!("sale    {sale_ref}");
                println!("pay     {outcome:?}");
                println!("tx      {tx_id}");
                explain_failure(&format!("{outcome:?}"));
                return Ok(());
            }

            let unsigned = IFaucet::new(&provider, max_epoch)
                .take_faucet_funds()
                .pay_fee(FAUCET_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let outcome = provider.send_transaction(tx).await?.watch().await?;
            println!("address {customer_address}");
            println!("account {}", customer_address.to_account_address());
            println!("faucet  {outcome:?}");
            eprintln!(
                "DEV BENCH: funded a customer account whose key lives on this \
                 workstation."
            );
        }
        // OPENING A STRANGER'S ACCOUNT, AND THE MERCHANT PAYS FOR IT.
        //
        // Found 2026-08-15 by building `ootle/pocket` and running it: a fresh
        // wallet prints a perfectly good address whose account substate is a
        // 404, `points_vault_of` returns None, and `award_for_sale` refuses to
        // send points at it — which is the guard working exactly as designed
        // (`issue_points` deposits into whatever it is handed and `withdraw`
        // is DenyAll, so points sent at a non-account are gone).
        //
        // **So the first customer of this programme cannot be given anything
        // until somebody pays a fee on their behalf.** That is a real product
        // gap and not a wallet defect: an account is a component, creating one
        // is a transaction, and a stranger who has never held XTR has nothing
        // to pay with. Asking them to acquire testnet funds before they can be
        // handed a loyalty point is not a shop, it is a homework assignment.
        //
        // `IAccount::public_transfer` already does it, and the reason is in
        // ootle-rs's own comment at `account.rs:113` — it asks for the
        // recipient's vault as NOT required, "if it doesn't exist, the
        // CreateAccount instruction will create it". So a transfer of any
        // positive amount opens the account as a side effect. This verb is
        // that, named for what it is for rather than for what it does, because
        // an operator standing in front of a customer is not thinking "public
        // transfer".
        //
        // **THE AMOUNT IS NOT THE POINT AND IS DELIBERATELY TINY.** What is
        // being bought is the existence of the account, not a balance. A
        // default that handed over real value would make this a verb somebody
        // has to think about before running, and the whole reason it exists is
        // that it should be the least interesting thing at the counter.
        "open-account" => {
            // `TARI_TOKEN` rather than `XTR`: the same constant, and the
            // latter is deprecated in favour of this name. Taking the
            // deprecation now costs nothing and is cheaper than meeting it
            // on the day the alias is removed.
            use ootle_rs::template_types::constants::TARI_TOKEN;

            let target = argv.get(2).ok_or(
                "open-account needs the customer's address - the `otl_esm_...` \
                 string their wallet prints, NOT their account component.\n\
                 `pocket address` prints it. Nothing about it is secret.",
            )?;
            let target: ootle_rs::Address = target.parse().map_err(|e| {
                format!(
                    "{target} is not an Ootle address ({e:?}). It should begin \
                     `otl_esm_` - a component address is a different thing and \
                     cannot be transferred to."
                )
            })?;
            // THE MERCHANT'S POLICY, not this binary's constant. See
            // `open_account_policy`: the terminal renders these two numbers as
            // a setting, and a setting nothing reads is decoration.
            let (policy_amount, per_day) = open_account_policy();
            let amount: u64 = match argv.get(3) {
                Some(raw) => raw
                    .parse()
                    .map_err(|e| format!("the amount must be a whole number ({e})"))?,
                None => policy_amount,
            };
            if amount == 0 {
                // A zero transfer would not create anything - `public_transfer`
                // panics on a non-positive amount - and refusing here says why
                // rather than aborting inside a library.
                return Err("a zero transfer opens nothing: it is the transfer \
                            that creates the account"
                    .into());
            }
            // AN EXPLICIT ARGUMENT IS AN OVERRIDE AND IS SAID OUT LOUD. It is
            // allowed - an operator standing at the counter may have a reason
            // this binary cannot know - but a spend that quietly differed from
            // the number on the settings screen is the thing the policy was
            // added to prevent.
            if amount != policy_amount {
                eprintln!(
                    "OVERRIDING THE MERCHANT'S POLICY: {amount} uT rather than \
                     the configured {policy_amount} uT.\nThe screen will keep \
                     saying {policy_amount}. Change merchant.json if you mean \
                     it every time."
                );
            }
            // THE DAILY LIMIT IS THE ONE THAT ACTUALLY BITES, and this binary
            // cannot enforce it: it is stateless, runs once per invocation and
            // keeps no ledger of what it has opened. Saying so is the honest
            // half - `CHARTER.md` §2 rule 6 - because a merchant who set the
            // number is entitled to know that nothing is counting.
            if per_day == 0 {
                return Err(format!(
                    "this merchant's policy is to open NO accounts \
                     (open_account_per_day is 0).\nNothing was submitted. \
                     Change it in merchant.json, or pass an amount explicitly \
                     if\nthis one customer is a deliberate exception."
                )
                .into());
            }
            eprintln!(
                "The configured limit is {per_day} a day. NOTHING COUNTS THEM: \
                 this tool is\nstateless and keeps no record of what it has \
                 opened, so that number is a\nbudget you are keeping, not one \
                 being enforced for you."
            );

            let account = target.to_account_address();
            println!("opening {account}");
            println!("  for   {target}");
            // microTari, NOT XTR, and the label was wrong until 2026-08-15.
            // `Amount::new` takes the smallest unit - 1 XTR is 1,000,000 of
            // them (`tari_template_lib_types` constants.rs:31) - so a line
            // reading "with 5 XTR" over a 5 uT transfer overstated it by six
            // orders of magnitude, on the one screen whose job is to say what
            // a merchant is about to spend.
            println!(
                "  with  {amount} microTari ({:.6} XTR), which is the fee for \
                 existing and not a balance",
                amount as f64 / 1_000_000.0
            );

            let unsigned = IAccount::new(&provider, max_epoch)
                .pay_fee(CALL_FEE)
                .public_transfer(&target, TARI_TOKEN, Amount::new(amount as u128))
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("open    {outcome:?}");
            explain_failure(&format!("{outcome:?}"));
            println!("tx      {tx_id}");
            eprintln!(
                "THE CUSTOMER OWNS THIS ACCOUNT AND THIS MACHINE CANNOT SPEND \
                 FROM IT.\nWhat was paid for is its existence: an account that \
                 can be awarded points and\ncan sign for itself. If the account \
                 already existed this was a small transfer\nand nothing else, \
                 which is why running it twice is harmless."
            );
        }
        "faucet" => {
            // ORDER IS LOAD-BEARING — see the module docs. take_faucet_funds()
            // emits create_account and claims a workspace slot; pay_fee then
            // pays from that slot. Reversed, as both sets of documentation
            // show it, the fee is charged to an account that does not exist.
            let unsigned = IFaucet::new(&provider, max_epoch)
                .take_faucet_funds()
                .pay_fee(FAUCET_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let outcome = provider.send_transaction(tx).await?.watch().await?;
            println!("address {address}");
            println!("faucet  {outcome:?}");
        }
        "publish" => {
            let file = argv.get(2).ok_or("publish needs a path to a .wasm file")?;
            let wasm = fs::read(file)?;
            // Printed BEFORE submitting, because fees scale with size and a
            // failed publish is the expected first outcome rather than a
            // surprise. The byte count is what makes the next fee guess better
            // than the last one.
            let budget = publish_fee(wasm.len());
            println!("publishing {file} ({} bytes, fee budget {budget})", wasm.len());
            let unsigned = IAccount::new(&provider, max_epoch)
                .pay_fee(budget)
                .publish_template(wasm)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("publish {outcome:?}");
            println!("tx      {tx_id}");
            // `watch()` returns a bare `TransactionOutcome::Commit` and throws
            // the detail away, so the address of the thing just published is
            // NOT in it. The receipt is where it lives, and fetching it is a
            // second round trip rather than something the submit path hands
            // back. Reported here so a publish is self-documenting: without
            // it, the only record of what was created is a tx id somebody has
            // to go and look up.
            report_receipt(&pending).await?;
        }
        "epoch" => {
            // THE QUESTION THIS WHOLE DETOUR EXISTS FOR. Everything
            // `harnesses/live_epoch.py` measured is the INDEXER's epoch
            // counter. Contract 5 denominates a membership term in the epoch a
            // TEMPLATE reads. Nothing had ever compared them.
            //
            // One transaction produces both witnesses: the receipt's `epoch`
            // is stamped by the executing validator, and the log line is
            // `Consensus::current_epoch()` as the template saw it during that
            // same execution. Read `/network` either side of this command and
            // there are three readings to line up.
            let template = argv.get(2).ok_or(
                "epoch needs the published template address \
                 (toolkit publish prints it as `created template_…`)",
            )?;
            let address: ootle_rs::template_types::TemplateAddress = template
                .strip_prefix("template_")
                .unwrap_or(template)
                .parse()
                .map_err(|e| format!("{template} is not a template address ({e:?})"))?;
            // IComponent, not IAccount. `IAccount` implements only
            // `UnsignedTransactionBuilder` (`account.rs:38`) - it has no
            // `call_function` and no `.then()` escape hatch. `IComponent` is
            // the generic invoker and the one that carries both. Checked in
            // source after `.then()` failed to resolve; the error names the
            // method, never the trait that is missing.
            let unsigned = IComponent::new(&provider, max_epoch)
                .call_function(address, "epoch_and_hash", vec![])
                .pay_fee(CALL_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("call    {outcome:?}");
            println!("tx      {tx_id}");
            report_receipt(&pending).await?;
        }
        "call" => {
            // Deliberately NO-ARGUMENT ONLY. Encoding arbitrary arguments
            // means a serialisation format on the command line, and the first
            // thing that reaches for is a string that has to become an
            // `Amount` or a `ComponentAddress` — a parser this tool would then
            // own and get subtly wrong. Constructors take nothing, which is
            // what this is for: publishing a template and standing up the
            // merchant's component. Anything with arguments belongs in a
            // typed call site, not in argv.
            let template = argv.get(2).ok_or("call needs a template address")?;
            let function = argv.get(3).ok_or("call needs a function name")?;
            let address: ootle_rs::template_types::TemplateAddress = template
                .strip_prefix("template_")
                .unwrap_or(template)
                .parse()
                .map_err(|e| format!("{template} is not a template address ({e:?})"))?;
            let unsigned = IComponent::new(&provider, max_epoch)
                .call_function(address, function.as_str(), vec![])
                .pay_fee(CALL_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("call    {outcome:?}");
            println!("tx      {tx_id}");
            report_receipt(&pending).await?;
        }
        // A contract with arguments gets a verb that knows its ABI, for the
        // reason `giftcard` and `loyalty` both give: the alternative is a
        // command-line parser guessing at a ResourceAddress and getting it
        // subtly wrong. Two arguments only, because this component does one
        // thing -- take money for a named sale.
        "payments" => {
            use ootle_rs::template_types::constants::TARI_TOKEN;

            let payments_verb = argv.get(2).map(String::as_str).unwrap_or("");
            if payments_verb != "deploy" && payments_verb != "pay" {
                return Err("payments verb must be `deploy` or `pay`".into());
            }

            // PAYING WITH THIS MACHINE'S OWN KEY, which is the merchant's. That
            // is a weaker claim than `devbench pay-sale` makes and it is worth
            // saying rather than glossing: it proves the component binds a real
            // deposit to a named sale on the real network, and it proves
            // nothing whatever about a stranger paying. The dev-bench key is
            // sealed and needs OOTLE_KEY_PASSPHRASE; when it is available,
            // `devbench pay-sale` is the same transaction signed by somebody
            // who is not the merchant.
            if payments_verb == "pay" {
                let component = argv
                    .get(3)
                    .ok_or("payments pay needs the component address, an amount, and a sale ref")?;
                let component: ComponentAddress = component
                    .strip_prefix("component_")
                    .unwrap_or(component)
                    .parse()
                    .map_err(|e| format!("{component} is not a component address ({e:?})"))?;
                let amount: u64 = argv
                    .get(4)
                    .ok_or("payments pay needs an amount in microTari")?
                    .parse()
                    .map_err(|e| format!("the amount must be a whole number of microTari ({e})"))?;
                if amount == 0 {
                    return Err("a zero payment settles nothing".into());
                }
                let sale_ref = argv
                    .get(5)
                    .ok_or("payments pay needs the sale reference the invoice printed")?
                    .clone();
                if sale_ref.is_empty() {
                    return Err("a payment must name the sale it is for".into());
                }

                // WHO PAYS. With no flags this machine pays, which proves the
                // component against the real network and proves nothing about a
                // stranger. `--member`/`--account` name a CUSTOMER instead --
                // both public and going together, the same pairing the loyalty
                // handoff uses -- and then `--compose` writes the transaction
                // out for that customer to sign somewhere else, so no process
                // ever holds both keys.
                let (payer_key, payer_account) = match (&member_flag, &account_flag) {
                    (Some(key), Some(account)) => {
                        let key: RistrettoPublicKeyBytes = key
                            .parse()
                            .map_err(|e| format!("--member is not a public key ({e:?})"))?;
                        let account: ComponentAddress = account
                            .strip_prefix("component_")
                            .unwrap_or(account)
                            .parse()
                            .map_err(|e| format!("--account is not a component address ({e:?})"))?;
                        (key, account)
                    }
                    (None, None) => (*address.account_public_key(), address.to_account_address()),
                    _ => {
                        return Err(
                            "--member and --account go together: both are public and they \
                             name the same customer. Giving one without the other would \
                             compose a transaction for an account nobody named."
                                .into(),
                        );
                    }
                };

                let unsigned = IComponent::new(&provider, max_epoch)
                    .want_vault_for(payer_account, TARI_TOKEN, true)
                    .then(|b| {
                        b.call_method(
                            payer_account,
                            "withdraw",
                            args![TARI_TOKEN, Amount::new(amount as u128)],
                        )
                        .put_last_instruction_output_on_workspace("payment")
                    })
                    .call_method(component, "pay", args![Workspace("payment"), sale_ref.clone()])
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?;

                // THE HANDOFF. Written out unsigned, holding no customer key
                // and creating none. The summary is the whole product here: it
                // is what a stranger reads before agreeing, and a signature is
                // consent to THIS sentence or it is consent to nothing.
                if let Some(path) = compose_to.as_deref() {
                    let request = SigningRequest {
                        summary: format!(
                            "Pay {amount} microTari from your account {payer_account} to the \
                             payment component {component}, recorded against sale reference \
                             {sale_ref}. The component credits this payment to that sale and \
                             to no other. It cannot refund you, and only the merchant can \
                             withdraw from it."
                        ),
                        kind: "payments-pay".to_string(),
                        network: format!("{NETWORK:?}").to_lowercase(),
                        // The sealer is in the signed message, so a signature
                        // over this request does not verify against a
                        // transaction sealed by anybody else.
                        seal_signer: pubkey_hex(address.account_public_key()),
                        member_key: pubkey_hex(&payer_key),
                        unsigned_cbor: to_hex(&tari_bor::encode(&unsigned)?),
                    };
                    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&request)?))?;
                    println!("composed {path}");
                    println!("  pays     {amount} uT for sale {sale_ref}");
                    println!("  from     {payer_account}");
                    println!("  needs a signature from {}", pubkey_hex(&payer_key));
                    println!("  sealed by              {}", pubkey_hex(address.account_public_key()));
                    println!(
                        "\nNothing was submitted and no fee was paid. Next:\n  \
                         pocket sign {path} <signature.json>              (the customer's \
                         machine)\n  toolkit submit-request {path} <signature.json>   \
                         (back here)"
                    );
                    return Ok(());
                }

                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("to      {component}");
                println!("amount  {amount} uT");
                println!("sale    {sale_ref}");
                println!("pay     {outcome:?}");
                println!("tx      {tx_id}");
                explain_failure(&format!("{outcome:?}"));
                return Ok(());
            }

            let template = argv
                .get(3)
                .ok_or("payments deploy needs the published template address")?;
            let template: ootle_rs::template_types::TemplateAddress = template
                .strip_prefix("template_")
                .unwrap_or(template)
                .parse()
                .map_err(|e| format!("{template} is not a template address ({e:?})"))?;

            // NAMED, not captured from the signer. `loyalty`'s constructor
            // records why capturing `transaction_signer_public_key()` was "the
            // defect rather than a detail of it": it makes the key permanent
            // and a theft of it terminal. This component has one key and no
            // recovery split, so the same trap is smaller but the same shape.
            let operating_key = *address.account_public_key();

            println!("deploying payments: accepts XTR, operated by this machine's key.");
            println!("  a payment names its sale, so two sales open at once cannot be confused.");
            let unsigned = IComponent::new(&provider, max_epoch)
                .call_function(template, "new", args![TARI_TOKEN, operating_key])
                .pay_fee(CALL_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("deploy  {outcome:?}");
            println!("tx      {tx_id}");
            explain_failure(&format!("{outcome:?}"));
            report_receipt(&pending).await?;
        }
        "giftcard" => {
            // A TYPED CALL SITE, WHICH IS THE POINT. `toolkit call` is
            // deliberately no-argument-only: encoding arbitrary arguments on a
            // command line means owning a parser that turns strings into
            // `Amount`s and `ComponentAddress`es, and getting that subtly
            // wrong is how a fee measurement becomes a fee fiction. So a
            // contract with arguments gets a verb that knows its ABI, and the
            // only thing parsed from argv is an integer.
            //
            // WHY THIS EXISTS AT ALL: to MEASURE. Publishing and constructing
            // were measured on 2026-07-28; what a merchant actually pays per
            // sale was not, and "plausibly low thousands of microtari" is
            // exactly the kind of sentence that put a wrong epoch in the docs.
            let verb = argv.get(2).map(String::as_str).unwrap_or("");

            // `deploy` is the odd one out: it takes a TEMPLATE and two
            // ceilings rather than a component and an amount, so it is handled
            // before the shared parsing below rather than bent to fit it.
            if verb == "deploy" {
                let template = argv.get(3).ok_or("deploy needs a template address")?;
                let per_card: u64 = argv
                    .get(4)
                    .ok_or("deploy needs a per-card ceiling in cents")?
                    .parse()
                    .map_err(|e| format!("per-card ceiling must be a whole number ({e})"))?;
                let per_epoch: u64 = argv
                    .get(5)
                    .ok_or("deploy needs a per-epoch ceiling in cents")?
                    .parse()
                    .map_err(|e| format!("per-epoch ceiling must be a whole number ({e})"))?;
                let template: ootle_rs::template_types::TemplateAddress = template
                    .strip_prefix("template_")
                    .unwrap_or(template)
                    .parse()
                    .map_err(|e| format!("{template} is not a template address ({e:?})"))?;
                // SET THESE GENEROUSLY. They ratchet down and never up, so a
                // number that turns out too high can be tightened tomorrow and
                // one that turns out too low is permanent.
                println!(
                    "deploying with ceilings: {per_card} cents per card, \
                     {per_epoch} per epoch (~34 min). Both tighten only."
                );
                let unsigned = IComponent::new(&provider, max_epoch)
                    .call_function(
                        template,
                        "new",
                        args![Amount::new(per_card as u128), Amount::new(per_epoch as u128)],
                    )
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("deploy  {outcome:?}");
                println!("tx      {tx_id}");
                report_receipt(&pending).await?;
                return Ok(());
            }

            let component = argv.get(3).ok_or("giftcard needs a component address")?;
            let cents: u64 = argv
                .get(4)
                .ok_or("giftcard needs an amount in cents")?
                .parse()
                .map_err(|e| format!("cents must be a whole number ({e})"))?;
            let component: ComponentAddress = component
                .strip_prefix("component_")
                .unwrap_or(component)
                .parse()
                .map_err(|e| format!("{component} is not a component address ({e:?})"))?;
            // Both verbs need the credit resource, and neither reads it off
            // the component: doing that would be a SECOND transaction with its
            // own fee, quietly inflating the number this verb exists to
            // measure. `live_giftcard.py` prints it, and so does
            // `toolkit call <template> new`.
            let credit = argv.get(5).ok_or(
                "giftcard needs the credit resource address as a 5th argument",
            )?;
            let credit: ResourceAddress = credit
                .strip_prefix("resource_")
                .unwrap_or(credit)
                .parse()
                .map_err(|e| format!("{credit} is not a resource address ({e:?})"))?;

            let me = address.to_account_address();
            let my_key = *address.account_public_key();
            // `Amount::new` takes u128 and there are no `From` impls to lean on -
            // checked in `tari_template_lib_types-0.29.0/src/amount/amount.rs`,
            // which offers `pub const fn new(amount: u128)` and nothing else.
            let amount = Amount::new(cents as u128);

            let unsigned = match verb {
                // issue -> Bucket. The bucket has to go somewhere in the same
                // transaction or the instruction set is unbalanced, so it is
                // deposited straight into this account. That makes the
                // merchant and the holder the same party here, which is fine
                // for a COST measurement and is not a flow anyone would ship:
                // see the note printed below.
                "issue" => IComponent::new(&provider, max_epoch)
                    // `required: false` IS THE WHOLE POINT, and it was found the
                    // expensive way. `create_account_with_bucket` creates the
                    // recipient's vault when it does not exist, so the FIRST
                    // card to a customer works with no want declared at all -
                    // and the SECOND fails with SubstateNotFound at instruction
                    // #3, because now the vault exists and was never asked for.
                    // Optional-want covers both: present it if it is there,
                    // create it if it is not. This is the same shape
                    // `IAccount::public_transfer` uses (`account.rs:106`).
                    .want_vault_for(me, credit, false)
                    .call_method(component, "issue", args![amount])
                    .then(|b| {
                        b.put_last_instruction_output_on_workspace("card")
                            .create_account_with_bucket(my_key, "card")
                    })
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?,
                // redeem takes the bucket, so the holder has to withdraw it
                // first. THIS IS THE TRANSACTION THE CUSTOMER SIGNS, and the
                // reason it is worth measuring separately: the gift card is
                // bearer, so the holder pushes, so the holder pays. A merchant
                // reading only the issue cost would be reading half the story.
                "redeem" => {
                    // The holder has to withdraw before they can hand anything
                    // over, and withdrawing names a resource. Taken from argv
                    // rather than read off the component, because reading it
                    // would be a SECOND transaction with its own fee - which
                    // would quietly inflate the very number this verb exists to
                    // measure. `live_giftcard.py` prints it, and so does
                    // `toolkit call <template> new`.
                    let credit = argv.get(5).ok_or(
                        "redeem needs the credit resource address as a 5th argument",
                    )?;
                    let credit: ResourceAddress = credit
                        .strip_prefix("resource_")
                        .unwrap_or(credit)
                        .parse()
                        .map_err(|e| format!("{credit} is not a resource address ({e:?})"))?;
                    // DECLARE THE HOLDER'S VAULT AS AN INPUT, or the withdraw
                    // fails with SubstateNotFound at instruction #1.
                    // `IComponent::call_method` auto-adds AllComponentVaults for
                    // the component it is CALLING (`component.rs:193`), but the
                    // withdraw below goes through `.then()` on the raw builder,
                    // which adds no wants at all. So the customer's own vault -
                    // the one holding the card - has to be asked for by hand.
                    // Measured the expensive way: the first attempt cost 260 uT
                    // and redeemed nothing.
                    IComponent::new(&provider, max_epoch)
                    .want_vault_for(me, credit, true)
                    .then(|b| {
                        b.call_method(me, "withdraw", args![credit, amount])
                            .put_last_instruction_output_on_workspace("spend")
                    })
                    .call_method(component, "redeem", args![Workspace("spend")])
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?
                }
                _ => return Err("giftcard verb must be `issue` or `redeem`".into()),
            };

            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("giftcard {verb} {cents} cents");
            println!("outcome {outcome:?}");
            println!("tx      {tx_id}");
            report_receipt(&pending).await?;
            println!(
                "NOTE    issuer and holder are the same account here. That is a \
                 cost measurement, not a flow: a real issue deposits into the \
                 CUSTOMER's account, which may add a SubstateCreate for a vault \
                 that does not exist yet."
            );
        }
        "loyalty" => {
            // Same reasoning as `giftcard`: a contract with arguments gets a
            // verb that knows its ABI, because the alternative is a
            // command-line parser guessing at `Amount` and getting it subtly
            // wrong. Note the ABI is NOT uniform — `Loyalty::new` takes a
            // plain u64 rate and then two `Amount` ceilings, so the encoding
            // below is not copy-paste from the gift card even though it looks
            // like it should be.
            let verb = argv.get(2).map(String::as_str).unwrap_or("");

            // ── `award` — the ONE write a merchant can make alone ──────────
            //
            // WHY THIS VERB EXISTS AND ITS SIBLINGS DO NOT, which is the whole
            // shape of the loyalty write path and is worth stating here rather
            // than discovering later.
            //
            // `issue_points` is gated on `public_key(merchant)` and nothing
            // else. Earning needs no signature from the customer, and that is
            // deliberate: a point being GIVEN takes nothing from them, so
            // asking them to sign for it would be friction bought with
            // nothing. The customer's account address is still needed - the
            // contract deposits into it - but an address is a scan, not a
            // signature.
            //
            // `enroll` and `redeem_points` are the opposite: both require
            // `get_signer_proof_for_public_key(member_key)`, so the CUSTOMER
            // must have signed the same transaction. A merchant's key alone
            // cannot move an enrolled customer's points, and that is the guard
            // working rather than a gap.
            //
            // **This comment used to say those two "CANNOT be done by this
            // binary at all, now or ever", and the correction is worth keeping
            // rather than quietly overwriting.** It was wrong because it
            // conflated a wallet with a signature: `ootle-rs` will hold a
            // second key and sign a composed transaction with it, no daemon
            // involved, which is what `enrol` and `redeem` below now do. What
            // a real customer needs is an application they already have that
            // will co-sign on request — a product, not a capability, and R2 on
            // the board. Holding both keys here proves the path and proves
            // nothing about consent.
            //
            // The lesson is the reusable part: "impossible" was load-bearing
            // in three documents and had never been checked against the crate.
            if verb == "award" {
                let component = argv.get(3).ok_or("award needs a component address")?;
                let to = argv.get(4).ok_or("award needs the customer's account address")?;
                let points: u64 = argv
                    .get(5)
                    .ok_or("award needs a number of points")?
                    .parse()
                    .map_err(|e| format!("points must be a whole number ({e})"))?;
                let sale_ref = argv.get(6).ok_or("award needs a sale reference")?;
                if points == 0 {
                    // The template asserts this too. Refusing here costs a
                    // round trip instead of a fee: the constructor's panic
                    // would arrive as a rejected transaction that still
                    // charged for the attempt.
                    return Err("a zero-point award is not an award".into());
                }
                if sale_ref.trim().is_empty() {
                    return Err("a points award with no sale reference cannot be \
                                reconciled - the template refuses it too"
                        .into());
                }
                let component: ComponentAddress = component
                    .parse()
                    .map_err(|e| format!("{component} is not a component address ({e:?})"))?;
                let to: ComponentAddress = to
                    .parse()
                    .map_err(|e| format!("{to} is not an account address ({e:?})"))?;

                // `required: false` for the same reason the gift card's issue
                // needs it, and it was found the expensive way there: the
                // FIRST award to a customer creates their points vault, so no
                // want can be declared; the SECOND fails with SubstateNotFound
                // if one is not. Optional-want covers both.
                let points_resource: ResourceAddress = argv
                    .get(7)
                    .ok_or("award needs the points resource address as a 7th argument - \
                            `live_loyalty.py` prints it, and reading it off the component \
                            here would be a second transaction with its own fee")?
                    .parse()
                    .map_err(|e| format!("not a resource address ({e:?})"))?;

                let unsigned = IComponent::new(&provider, max_epoch)
                    .want_vault_for(to, points_resource, false)
                    .call_method(
                        component,
                        "issue_points",
                        args![to, Amount::new(points as u128), sale_ref.to_string()],
                    )
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("award   {outcome:?}");
                explain_failure(&format!("{outcome:?}"));
                println!("tx      {tx_id}");
                report_receipt(&pending).await?;
                return Ok(());
            }

            // ── `award-batch` — N awards in ONE transaction ────────────────
            //
            // BUILT TO MEASURE, and kept because it is the thing the terminal
            // would eventually call. `2026-08-14-loyalty-fees.json` found that
            // `TemplateLoad` is a flat 1,080 µT charged per TRANSACTION rather
            // than per instruction — 31% of an award — and left the rest of the
            // question open: `Storage` is charged per substate written, and an
            // award writes both the shared component state and the recipient's
            // own vault, so part of it should amortise across a batch and part
            // should not. That split was bounded and not measured.
            //
            // This verb is what measures it. The interesting comparison is not
            // one batch against one award but TWO batches against each other:
            // N awards to the SAME account write one vault, N awards to
            // DIFFERENT accounts write N, and the difference between those two
            // is the per-recipient storage cost with everything else held
            // constant.
            if verb == "award-batch" {
                let component = argv.get(3).ok_or("award-batch needs a component address")?;
                let component: ComponentAddress = component
                    .parse()
                    .map_err(|e| format!("{component} is not a component address ({e:?})"))?;
                let points_resource = argv
                    .get(4)
                    .ok_or("award-batch needs the points resource address as a 4th argument")?;
                let points_resource: ResourceAddress = points_resource
                    .strip_prefix("resource_")
                    .unwrap_or(points_resource)
                    .parse()
                    .map_err(|e| format!("not a resource address ({e:?})"))?;

                let specs = argv.get(5..).unwrap_or(&[]);
                if specs.is_empty() {
                    return Err("award-batch needs at least one <account>:<points>:<sale-ref>".into());
                }
                let mut awards = Vec::new();
                for spec in specs {
                    let parts: Vec<&str> = spec.split(':').collect();
                    if parts.len() != 3 {
                        return Err(format!(
                            "`{spec}` is not <account>:<points>:<sale-ref>"
                        )
                        .into());
                    }
                    let to: ComponentAddress = parts[0]
                        .parse()
                        .map_err(|e| format!("{} is not an account address ({e:?})", parts[0]))?;
                    let points: u64 = parts[1]
                        .parse()
                        .map_err(|e| format!("points must be a whole number ({e})"))?;
                    if points == 0 {
                        return Err("a zero-point award is not an award".into());
                    }
                    if parts[2].trim().is_empty() {
                        return Err("every award in a batch needs its own sale reference - \
                                    the template refuses an empty one, and a batch that \
                                    shared one could not be reconciled per sale"
                            .into());
                    }
                    awards.push((to, points, parts[2].to_string()));
                }

                let mut builder = IComponent::new(&provider, max_epoch);
                // Optional-want for each distinct recipient, same reasoning as
                // the single `award`: the first award to somebody creates their
                // vault so no want can be declared, and the second fails with
                // SubstateNotFound if one is not. Duplicates collapse — the
                // want list is a set — so N awards to one account declare one.
                for (to, _, _) in &awards {
                    builder = builder.want_vault_for(*to, points_resource, false);
                }
                for (to, points, sale_ref) in &awards {
                    builder = builder.call_method(
                        component,
                        "issue_points",
                        args![*to, Amount::new(*points as u128), sale_ref.clone()],
                    );
                }
                // Budget scaled by the batch and then some. Overpaying is free
                // and underpaying forfeits the whole attempt — `CHARTER.md` §4,
                // and the asymmetry is measured rather than assumed.
                let budget = CALL_FEE * (awards.len() as u64 + 1);
                let unsigned = builder.pay_fee(budget).prepare().await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                let distinct: std::collections::HashSet<_> =
                    awards.iter().map(|(to, _, _)| to).collect();
                println!("batch   {outcome:?}");
                explain_failure(&format!("{outcome:?}"));
                println!("awards  {} to {} distinct account(s)", awards.len(), distinct.len());
                println!("budget  {budget}");
                println!("tx      {tx_id}");
                report_receipt(&pending).await?;
                return Ok(());
            }

            // ── `enrol` and `redeem` — the two that need the customer ──────
            //
            // THE COMMENT ABOVE SAID THESE COULD NOT BE DONE BY THIS BINARY
            // "now or ever", and that was wrong in a specific and useful way.
            // It conflated a wallet with a signature. Both methods need the
            // member's key to have signed the merchant's transaction, and
            // `ootle-rs` composes exactly that without any daemon:
            //
            //   * `OotleWallet::register_key_provider` holds a second key
            //     alongside the merchant's, with the merchant still default;
            //   * `authorize_transaction(addr, &unsigned)` signs the composed,
            //     unsealed transaction with that second key — the message is
            //     `TransactionSignature::create_message(seal_signer, unsigned)`,
            //     so the signature commits to the merchant's whole transaction
            //     and to the merchant as its sealer;
            //   * `TransactionRequest::add_authorization` attaches it, and
            //     `build()` then seals with the merchant's key.
            //
            // Signing and sealing being separate steps is what makes
            // merchant-composes / customer-consents expressible. So what is
            // missing for a real customer is a WALLET — an application a
            // stranger already has, that can be handed a transaction and asked
            // to co-sign it. That is a product, and it is R2 on the board.
            //
            // WHAT THIS VERB IS, THEREFORE. A dev bench holding both keys,
            // proving the contract's path executes on the real network. It is
            // NOT a customer consenting, it is not evidence for criteria 8 and
            // 9, and `cosigned_banner` says so on every run.
            if verb == "enrol" || verb == "redeem" {
                // WHO THE CUSTOMER IS, and there are two ways to know.
                //
                // The old way derives both halves from a key file sitting on
                // this machine, which is what makes the dev bench a dev bench.
                // The handoff way is given them: an account address and a
                // public key are things a customer can hand over on a screen or
                // a QR, and neither is a secret — `board/IN_PROGRESS.md` B4,
                // "an address is a scan, not a signature". They are supplied
                // together because a mismatched pair produces a transaction the
                // contract refuses after the fee.
                let (member_key, customer_account) = match (&member_flag, &account_flag) {
                    (Some(key), Some(account)) => {
                        let key: RistrettoPublicKeyBytes = key.parse().map_err(|e| {
                            format!("--member is not a public key ({e:?})")
                        })?;
                        let account: ComponentAddress = account
                            .strip_prefix("component_")
                            .unwrap_or(account)
                            .parse()
                            .map_err(|e| {
                                format!("--account is not a component address ({e:?})")
                            })?;
                        (key, account)
                    }
                    (None, None) => {
                        let customer_address = customer_address.as_ref().ok_or(
                            "no customer key is loaded and no --member/--account pair \
                             was given",
                        )?;
                        (
                            *customer_address.account_public_key(),
                            customer_address.to_account_address(),
                        )
                    }
                    _ => {
                        return Err("--member and --account go together: the public key \
                                    says who signs, the account says where the points \
                                    live, and one without the other cannot compose a \
                                    transaction"
                            .into());
                    }
                };

                let component = argv.get(3).ok_or("needs the loyalty component address")?;
                let component: ComponentAddress = component
                    .parse()
                    .map_err(|e| format!("{component} is not a component address ({e:?})"))?;

                // The points resource, for the same reason `award` takes it:
                // reading it off the component would be a second transaction
                // with its own fee. Both verbs need it, but for DIFFERENT
                // reasons, and the difference is worth stating because it is
                // the non-obvious half of this whole verb pair.
                //
                //   * `enrol` reads the customer's vault to check it is the one
                //     their account receives into, so the vault must be an
                //     input.
                //   * `redeem` never NAMES a vault — it reads one out of the
                //     enrolment record the customer co-signed, which is the
                //     guard that stops a redemption being pointed at somebody
                //     else's points. That vault is therefore invisible to the
                //     input resolver, which only sees the instruction's
                //     arguments. Wanted explicitly here, or the recall inside
                //     the template hits a substate the transaction never asked
                //     for.
                let points_resource = argv.get(4).ok_or(
                    "needs the points resource address — `live_loyalty.py` prints it, \
                     and reading it off the component here would be a second \
                     transaction with its own fee",
                )?;
                let points_resource: ResourceAddress = points_resource
                    .strip_prefix("resource_")
                    .unwrap_or(points_resource)
                    .parse()
                    .map_err(|e| format!("not a resource address ({e:?})"))?;

                let unsigned = if verb == "enrol" {
                    // The vault is an ARGUMENT to `enroll` and the contract
                    // checks it against the account, so it is named rather than
                    // discovered. `live_enrol.py` reads it off the indexer and
                    // passes it in, which is also the only way this tool can be
                    // pointed at a vault it did not derive itself.
                    let vault = argv.get(5).ok_or(
                        "enrol needs the customer's points vault id as a 5th argument",
                    )?;
                    let vault: VaultId = vault
                        .strip_prefix("vault_")
                        .unwrap_or(vault)
                        .parse()
                        .map_err(|e| format!("{vault} is not a vault id ({e:?})"))?;
                    IComponent::new(&provider, max_epoch)
                        .want_vault_for(customer_account, points_resource, true)
                        .call_method(
                            component,
                            "enroll",
                            args![customer_account, member_key, vault],
                        )
                        .pay_fee(CALL_FEE)
                        .prepare()
                        .await?
                } else {
                    let points: u64 = argv
                        .get(5)
                        .ok_or("redeem needs a number of points")?
                        .parse()
                        .map_err(|e| format!("points must be a whole number ({e})"))?;
                    let sale_ref = argv.get(6).ok_or("redeem needs a sale reference")?;
                    if points == 0 {
                        return Err("a zero-point redemption is not a redemption".into());
                    }
                    if sale_ref.trim().is_empty() {
                        return Err("a redemption with no sale reference cannot be \
                                    reconciled - the template refuses it too"
                            .into());
                    }
                    // THE ENROLMENT RECORD, ASKED FOR BY ID.
                    //
                    // Measured, not predicted: the first attempt declared the
                    // vault and nothing else and came back
                    // `OnlyFeeCommit(SubstateNotFound)` at instruction #1,
                    // naming this NFT. `redeem_points` looks the enrolment up
                    // by `NonFungibleId::from_public_key(member_key)` and reads
                    // the vault OUT of it, which is exactly what stops a
                    // redemption being pointed at somebody else's points — so
                    // the record it depends on is invisible to a resolver that
                    // sees only arguments. A contract whose guard is "do not
                    // take this from the caller" makes its own inputs
                    // underivable, and that is a property worth expecting in
                    // the next one rather than rediscovering.
                    let enrolments = argv.get(7).ok_or(
                        "redeem needs the enrolments resource address as a 7th argument - \
                         the enrolment NFT is read from the register rather than passed \
                         in, so the transaction has to declare it as an input by id",
                    )?;
                    let enrolments: ResourceAddress = enrolments
                        .strip_prefix("resource_")
                        .unwrap_or(enrolments)
                        .parse()
                        .map_err(|e| format!("not a resource address ({e:?})"))?;
                    let record = SubstateId::NonFungible(NonFungibleAddress::new(
                        enrolments,
                        NonFungibleId::from_public_key(member_key),
                    ));
                    IComponent::new(&provider, max_epoch)
                        .want_vault_for(customer_account, points_resource, true)
                        .want_substate(record, true)
                        .call_method(
                            component,
                            "redeem_points",
                            args![member_key, Amount::new(points as u128), sale_ref.to_string()],
                        )
                        .pay_fee(CALL_FEE)
                        .prepare()
                        .await?
                };

                // STEP 1 OF THE HANDOFF ENDS HERE. With `--compose` the
                // transaction goes to a file instead of to a signature, and
                // this process stops — having never held, asked for or created
                // the customer's key. Everything above ran identically, which
                // is the property worth having: the composed transaction is the
                // same one the all-in-one path builds, so a request that
                // succeeds here is a transaction that would have succeeded
                // there.
                if let Some(path) = &compose_to {
                    let summary = if verb == "enrol" {
                        format!(
                            "Enrol {} as a loyalty member of {}, binding their points \
                             vault to their account.",
                            pubkey_hex(&member_key),
                            component
                        )
                    } else {
                        format!(
                            "Redeem {} points from {}'s balance on {}.",
                            argv.get(5).map(String::as_str).unwrap_or("?"),
                            pubkey_hex(&member_key),
                            component
                        )
                    };
                    let request = SigningRequest {
                        summary,
                        kind: format!("loyalty-{verb}"),
                        network: format!("{NETWORK:?}").to_lowercase(),
                        // THE SEALER IS THIS MACHINE, and it is in the signed
                        // message. A signature over this request does not
                        // verify against a transaction sealed by anybody else,
                        // so the request cannot be replayed by a third party
                        // who intercepts it.
                        seal_signer: pubkey_hex(address.account_public_key()),
                        member_key: pubkey_hex(&member_key),
                        unsigned_cbor: to_hex(&tari_bor::encode(&unsigned)?),
                    };
                    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&request)?))?;
                    println!("composed {path}");
                    println!("  needs a signature from {}", pubkey_hex(&member_key));
                    println!("  sealed by              {}", pubkey_hex(address.account_public_key()));
                    println!(
                        "\nNothing was submitted and no fee was paid. Next:\n  \
                         toolkit sign-request {path} <signature.json>   (the customer's \
                         machine)\n  toolkit submit-request {path} <signature.json>   \
                         (back here)"
                    );
                    return Ok(());
                }

                // THE CO-SIGNATURE. Produced against the composed transaction
                // and the merchant's public key as its sealer, so it cannot be
                // lifted onto a different transaction than the one the customer
                // was shown.
                let customer_address = customer_address.as_ref().ok_or(
                    "no customer key is loaded, so this transaction cannot be \
                     co-signed here. Use --compose to write it out for somebody \
                     else to sign.",
                )?;
                let consent = provider
                    .wallet()
                    .authorize_transaction(customer_address, &unsigned)
                    .await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .add_authorization(consent)
                    .build(provider.wallet())
                    .await?;
                cosigned_banner();
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("{verb}   {outcome:?}");
                explain_failure(&format!("{outcome:?}"));
                println!("member  {member_key}");
                println!("account {customer_account}");
                println!("tx      {tx_id}");
                report_receipt(&pending).await?;
                return Ok(());
            }

            // ── ROTATION ──────────────────────────────────────────────────
            //
            // The verb the whole two-key shape exists to make possible. Signed
            // by the RECOVERY key (see the wallet setup above), which is why it
            // is the one loyalty verb this machine's own key cannot perform.
            if verb == "rotate" {
                let component = argv.get(3).ok_or(
                    "rotate needs the loyalty component address, then optionally the new \
                     operating public key.\nWith no key it hands operation to THIS machine, \
                     which is the usual case: you are\nstanding at the replacement till.",
                )?;
                let component: ComponentAddress = component
                    .strip_prefix("component_")
                    .unwrap_or(component)
                    .parse()
                    .map_err(|e| format!("{component} is not a component address ({e:?})"))?;

                // Defaults to this machine, because the common case is a
                // merchant standing at the new till wanting it to take over.
                // An explicit key covers handing operation to a machine that is
                // not this one.
                let new_key = match argv.get(4) {
                    Some(k) => k
                        .parse()
                        .map_err(|e| format!("{k} is not a public key ({e:?})"))?,
                    None => *address.account_public_key(),
                };

                println!(
                    "rotating {component}\n  new operating key {}\n  signed by the recovery key",
                    pubkey_hex(&new_key)
                );
                println!(
                    "\nThe key being replaced stops working the moment this commits. Anything \
                     mid-flight\nsigned by it will fail — which is the point, and is what makes \
                     this worth doing the\nmoment a till goes missing rather than after an \
                     investigation."
                );

                let unsigned = IComponent::new(&provider, max_epoch)
                    .call_method(component, "rotate_operating_key", args![new_key])
                    .pay_fee(CALL_FEE)
                    .prepare()
                    .await?;
                // The till pays; the recovery key only consents. See the wallet
                // setup above for why sealing with the recovery key was wrong.
                let recovery_address = recovery_address.ok_or("no recovery key was loaded")?;
                let consent = provider
                    .wallet()
                    .authorize_transaction(&recovery_address, &unsigned)
                    .await?;
                let tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .add_authorization(consent)
                    .build(provider.wallet())
                    .await?;
                let pending = provider.send_transaction(tx).await?;
                let tx_id = pending.tx_id();
                let outcome = pending.watch().await?;
                println!("rotate  {outcome:?}");
                explain_failure(&format!("{outcome:?}"));
                println!("tx      {tx_id}");
                report_receipt(&pending).await?;
                return Ok(());
            }

            if verb != "deploy" {
                return Err(
                    "loyalty verb must be `deploy`, `award`, `enrol`, `redeem` or `rotate`".into(),
                );
            }
            let template = argv.get(3).ok_or("deploy needs a template address")?;
            let rate: u64 = argv
                .get(4)
                .ok_or("deploy needs a redemption rate in points per cent")?
                .parse()
                .map_err(|e| format!("the rate must be a whole number ({e})"))?;
            let per_issue: u64 = argv
                .get(5)
                .ok_or("deploy needs a per-issue ceiling in points")?
                .parse()
                .map_err(|e| format!("per-issue ceiling must be a whole number ({e})"))?;
            let per_epoch: u64 = argv
                .get(6)
                .ok_or("deploy needs a per-epoch ceiling in points")?
                .parse()
                .map_err(|e| format!("per-epoch ceiling must be a whole number ({e})"))?;

            // THE RECOVERY KEY IS REQUIRED AND HAS NO DEFAULT, deliberately.
            //
            // It gates rotation and both ratchets, it is baked into the access
            // rules under `OwnerRule::None`, and it can never be changed. No
            // fallback here would be right: defaulting to this toolkit's own
            // key would put the recovery key on the till — the one place K1
            // says it must never be — producing a component that is shape A
            // with a rotation method the thief also holds. `Loyalty::new`
            // refuses two equal keys, so a defaulted flag would turn a silent
            // mistake into a failed deploy. Better, and still a deploy nobody
            // meant to attempt.
            //
            // The OPERATING key is not asked for: it is this toolkit's signer,
            // because that is the till, and it is the half designed to be
            // replaceable.
            let recovery_key = argv.get(7).ok_or(
                "deploy needs a recovery public key as its last argument. It gates \
                 rotation and both ratchets, it can NEVER be changed after this call, \
                 and it must not be a key that lives on this machine. \
                 See board/IN_PROGRESS.md K1",
            )?;
            let recovery_key = recovery_key
                .parse()
                .map_err(|e| format!("the recovery key is not a public key ({e:?})"))?;

            // The till's own key. This is the half that rotates, so naming it
            // explicitly costs nothing and means the constructor cannot be
            // handed the wrong signer by a deploy run from the wrong machine.
            let operating_key = *address.account_public_key();
            if operating_key == recovery_key {
                return Err(
                    "the recovery key is this machine's own key. That is shape A with \
                     extra steps: the key that lives on the till would also be the key \
                     that can ratchet the ceilings to the floor, and no rotation could \
                     take that back. Generate the recovery key somewhere else"
                        .into(),
                );
            }

            let template: ootle_rs::template_types::TemplateAddress = template
                .strip_prefix("template_")
                .unwrap_or(template)
                .parse()
                .map_err(|e| format!("{template} is not a template address ({e:?})"))?;

            // THE RATE IS THE ONE THAT CANNOT BE UNDONE OR NARROWED. The two
            // ceilings ratchet tighter; the rate has no setter and no
            // tightening path at all, because there is no safe direction for
            // it to move in — a rate that could only ever fall would still be
            // a rate that moved after somebody earned at the old one.
            println!(
                "deploying loyalty: {rate} points per cent (PERMANENT, no setter), \
                 ceilings {per_issue} points per award and {per_epoch} per epoch \
                 (both tighten only)."
            );
            let unsigned = IComponent::new(&provider, max_epoch)
                .call_function(
                    template,
                    "new",
                    args![
                        rate,
                        Amount::new(per_issue as u128),
                        Amount::new(per_epoch as u128),
                        operating_key,
                        recovery_key
                    ],
                )
                .pay_fee(CALL_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("deploy  {outcome:?}");
            println!("tx      {tx_id}");
            report_receipt(&pending).await?;
        }
        // Contracts 4 and 5 take one `Amount` each, which is the whole reason
        // they get verbs rather than riding on `call`: `call` handles
        // no-argument functions only, and a generic argument parser guessing at
        // `Amount` encoding is the mistake the gift card and loyalty verbs
        // already exist to avoid.
        //
        // Both ceilings are counts of tokens, not money — registrations per
        // epoch and grants per epoch. Neither contract mints anything
        // denominated, so there is no per-issue figure to pair them with: one
        // call mints exactly one token.
        cmd @ ("warranty" | "membership") => {
            let verb = argv.get(2).map(String::as_str).unwrap_or("");
            if verb != "deploy" {
                return Err(format!("{cmd} verb must be `deploy`").into());
            }
            let template = argv.get(3).ok_or("deploy needs a template address")?;
            let unit = if cmd == "warranty" { "registrations" } else { "grants" };
            let per_epoch: u64 = argv
                .get(4)
                .ok_or_else(|| format!("deploy needs a per-epoch ceiling in {unit}"))?
                .parse()
                .map_err(|e| format!("the per-epoch ceiling must be a whole number ({e})"))?;
            if per_epoch == 0 {
                // The template asserts this too. Refusing here as well costs a
                // round trip instead of a fee, and the constructor's panic
                // would arrive as a rejected transaction that still charged.
                return Err("a ceiling of zero would make the contract unable to issue".into());
            }
            let template: ootle_rs::template_types::TemplateAddress = template
                .strip_prefix("template_")
                .unwrap_or(template)
                .parse()
                .map_err(|e| format!("{template} is not a template address ({e:?})"))?;

            let function = if cmd == "warranty" { "Warranty" } else { "Membership" };
            println!(
                "deploying {cmd} ({function}::new): ceiling {per_epoch} {unit} per epoch \
                 (tightens only — there is no method that raises it)."
            );
            let unsigned = IComponent::new(&provider, max_epoch)
                .call_function(template, "new", args![Amount::new(per_epoch as u128)])
                .pay_fee(CALL_FEE)
                .prepare()
                .await?;
            let tx = TransactionRequest::default()
                .with_transaction(unsigned)
                .build(provider.wallet())
                .await?;
            let pending = provider.send_transaction(tx).await?;
            let tx_id = pending.tx_id();
            let outcome = pending.watch().await?;
            println!("deploy  {outcome:?}");
            println!("tx      {tx_id}");
            report_receipt(&pending).await?;
        }
        "finality" => {
            // OOTLE_SCOPE.md open question 3, closed with measurements rather
            // than a protocol reputation. Same gift-card issue/redeem path the
            // fee measurement used, with Instant around send_transaction and
            // watch(). Issuer and holder are the same account — that is a
            // finality measurement, not a customer flow.
            //
            // TWO numbers come out, not one, and the difference between them
            // is the finding: Ootle commits on a cadence, so what you measure
            // depends on WHEN you submit relative to that cadence. See the
            // `phase` field on FinalitySample.
            let component = argv.get(2).ok_or(
                "finality needs a component address \
                 (see live_giftcard.py COMPONENT)",
            )?;
            let credit = argv.get(3).ok_or(
                "finality needs the credit resource address \
                 (see live_giftcard.py CREDIT)",
            )?;
            let n: u32 = argv
                .get(4)
                .map(|s| s.parse())
                .transpose()
                .map_err(|e| format!("n must be a whole number ({e})"))?
                .unwrap_or(5);
            let cents: u64 = argv
                .get(5)
                .map(|s| s.parse())
                .transpose()
                .map_err(|e| format!("cents must be a whole number ({e})"))?
                .unwrap_or(100);
            if n == 0 {
                return Err("n must be at least 1".into());
            }
            if cents == 0 {
                return Err("cents must be at least 1".into());
            }

            let component: ComponentAddress = component
                .strip_prefix("component_")
                .unwrap_or(component)
                .parse()
                .map_err(|e| format!("{component} is not a component address ({e:?})"))?;
            let credit: ResourceAddress = credit
                .strip_prefix("resource_")
                .unwrap_or(credit)
                .parse()
                .map_err(|e| format!("{credit} is not a resource address ({e:?})"))?;

            let me = address.to_account_address();
            let my_key = *address.account_public_key();
            let amount = Amount::new(cents as u128);
            let indexer = ootle_rs::default_indexer_url(NETWORK).to_string();

            // Resolved BEFORE a single transaction is submitted, so a run can
            // never spend testnet XTR and then discover it has nowhere safe to
            // land. Printed for the same reason: the operator should know
            // where the answer is going before they pay for it.
            let out = finality_out_path();
            if let Some(dir) = out.parent() {
                fs::create_dir_all(dir)?;
            }

            println!(
                "finality: {n} issue+redeem pairs, {cents} cents each, \
                 timeout {}s, indexer {indexer}",
                TX_TIMEOUT.as_secs()
            );
            println!("will write {}", out.display());

            let mut samples: Vec<FinalitySample> = Vec::with_capacity((n * 2) as usize);

            // Shared body for one timed submit→watch. Built as a closure so
            // issue and redeem share the clock split without duplicating the
            // receipt / error handling that is the whole point of the sample.
            #[allow(clippy::too_many_arguments)]
            async fn timed_call(
                provider: &mut ootle_rs::provider::IndexerProvider<OotleWallet>,
                action: &'static str,
                phase: &'static str,
                stagger_ms: u64,
                run: u32,
                cents: u64,
                unsigned: tari_ootle_transaction::UnsignedTransaction,
            ) -> FinalitySample {
                let build_tx = TransactionRequest::default()
                    .with_transaction(unsigned)
                    .build(provider.wallet())
                    .await;
                let tx = match build_tx {
                    Ok(t) => t,
                    Err(e) => {
                        return FinalitySample {
                            run,
                            action,
                            phase,
                            stagger_ms,
                            cents,
                            tx_id: None,
                            outcome: "build_error".into(),
                            committed: false,
                            timed_out: false,
                            submit_ms: 0,
                            finality_ms: 0,
                            total_ms: 0,
                            fees_paid_ut: None,
                            epoch: None,
                            error: Some(e.to_string()),
                        };
                    }
                };

                let t_submit = Instant::now();
                let pending = match provider.send_transaction(tx).await {
                    Ok(p) => p,
                    Err(e) => {
                        let submit_ms = t_submit.elapsed().as_millis() as u64;
                        return FinalitySample {
                            run,
                            action,
                            phase,
                            stagger_ms,
                            cents,
                            tx_id: None,
                            outcome: "submit_error".into(),
                            committed: false,
                            timed_out: false,
                            submit_ms,
                            finality_ms: 0,
                            total_ms: submit_ms,
                            fees_paid_ut: None,
                            epoch: None,
                            error: Some(e.to_string()),
                        };
                    }
                };
                let submit_ms = t_submit.elapsed().as_millis() as u64;
                let tx_id = pending.tx_id().to_string();

                let t_watch = Instant::now();
                let watch_result = pending.watch().await;
                let finality_ms = t_watch.elapsed().as_millis() as u64;
                let total_ms = submit_ms + finality_ms;

                match watch_result {
                    Ok(outcome) => {
                        let committed = outcome.is_commit();
                        let outcome_s = format!("{outcome:?}");
                        // Receipt only exists for terminal results the indexer
                        // kept; a pure reject may still have one when fees
                        // were taken. Best-effort: absence is recorded as
                        // None, not as a sample failure.
                        let (fees_paid_ut, epoch) = if committed || outcome.is_only_fee_commit() {
                            match pending.get_receipt().await {
                                Ok(r) => (
                                    Some(r.fee_receipt().total_fees_paid()),
                                    Some(r.epoch().as_u64()),
                                ),
                                Err(_) => (None, None),
                            }
                        } else {
                            (None, None)
                        };
                        FinalitySample {
                            run,
                            action,
                            phase,
                            stagger_ms,
                            cents,
                            tx_id: Some(tx_id),
                            outcome: outcome_s,
                            committed,
                            timed_out: false,
                            submit_ms,
                            finality_ms,
                            total_ms,
                            fees_paid_ut,
                            epoch,
                            error: None,
                        }
                    }
                    Err(e) => {
                        let timed_out = e.is_timeout();
                        FinalitySample {
                            run,
                            action,
                            phase,
                            stagger_ms,
                            cents,
                            tx_id: Some(tx_id),
                            outcome: if timed_out {
                                "timeout".into()
                            } else {
                                "error".into()
                            },
                            committed: false,
                            timed_out,
                            submit_ms,
                            finality_ms,
                            total_ms,
                            fees_paid_ut: None,
                            epoch: None,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }

            // A `prepare()` that fails must not throw away the run.
            //
            // Every failure INSIDE `timed_call` already becomes a sample, but
            // the two `prepare()` calls below used `?`, which unwinds out of
            // `main` before anything is written — so a transient error on the
            // last pair discarded four good pairs AND the testnet XTR already
            // spent on them. `?` is right when the next line is the point of
            // the program; here the accumulated samples are, so a prepare
            // failure is recorded like any other and the loop moves on.
            macro_rules! prepared {
                ($action:expr, $phase:expr, $stagger:expr, $run:expr, $build:expr) => {
                    match $build.prepare().await {
                        Ok(u) => u,
                        Err(e) => {
                            let s = FinalitySample {
                                run: $run,
                                action: $action,
                                phase: $phase,
                                stagger_ms: $stagger,
                                cents,
                                tx_id: None,
                                outcome: "prepare_error".into(),
                                committed: false,
                                timed_out: false,
                                submit_ms: 0,
                                finality_ms: 0,
                                total_ms: 0,
                                fees_paid_ut: None,
                                epoch: None,
                                error: Some(e.to_string()),
                            };
                            println!("  [{}/{n}] {} prepare failed: {e}", $run, $action);
                            samples.push(s);
                            continue;
                        }
                    }
                };
            }

            for run in 1..=n {
                // ── the stagger, which is what makes the issue samples mean
                //    what a merchant thinks they mean ────────────────────
                //
                // Ootle commits on a cadence. Submitting the next transaction
                // the instant the last one committed locks onto that cadence
                // and measures a full cycle every time — which is why the
                // first version of this command reported a 724 ms spread
                // across twelve samples and called it a latency distribution.
                //
                // So each pair after the first waits a slice of one cycle
                // before issuing, sweeping the phase space evenly. The cycle
                // length is not assumed — it is taken from the locked samples
                // already collected, which measure exactly that. Deterministic
                // on purpose: a fixed sweep covers the space more evenly than
                // random draws at these sample sizes, and it reproduces.
                //
                // MIDPOINT SAMPLING, and this has now been wrong TWICE — in
                // opposite directions, which is the useful part.
                //
                // First wrong: offsets of (i-1)/n put a sample at phase 0 — a
                // full cycle's wait — but never near phase 1, where the wait
                // is ~0. That sweep is asymmetric, and its median came out
                // 34.7 s against a true half-cycle of 29.2 s: biased 19% HIGH.
                // Offsets of (i-0.5)/n are symmetric about the half cycle, so
                // the sample median is an unbiased estimate of it.
                //
                // ⚠ SECOND WRONG, AND SUBTLER: THE FIRST PAIR CANNOT BE
                // STAGGERED, SO IT IS NOT A SAMPLE OF THE SWEEP. The stagger
                // is a fraction of a MEASURED cycle, and before run 1 nothing
                // has measured one — so run 1 always went out at offset 0 and
                // the sweep it belonged to was never run. Written as (2i-1)/2n
                // over i=1..n, that silently dropped the lowest offset,
                // 1/(2n), and kept the other n-1 — whose mean is (n+1)/2n, not
                // 1/2. For n=6 the controlled samples then median 16.7% LOW,
                // and low is the FLATTERING direction: it understates what a
                // customer waits, which is the error this instrument exists to
                // avoid making.
                //
                // On 2026-07-31 that went unnoticed because run 1's untimed
                // sample happened to land at 51.7 s, near the top of the
                // range, dragging the six-sample median back to 29,159 ms —
                // 0.6% from the half-cycle. Luck, not design. Had it landed
                // near 5 s the same run would have reported 19,347 ms, 34%
                // low, with every other number identical.
                //
                // So the sweep is now taken over the runs that CAN carry one —
                // j = 1..(n-1) for runs 2..n — and run 1's issue is labelled
                // `unknown` rather than `free`. Its phase genuinely is unknown;
                // calling it free is what let it into the free-phase median in
                // the first place. One sample is given up and the estimator
                // stops depending on where that sample happens to fall.
                let cycle_hint = {
                    let mut locked: Vec<u64> = samples
                        .iter()
                        .filter(|s| s.committed && s.phase == "locked")
                        .map(|s| s.finality_ms)
                        .collect();
                    locked.sort_unstable();
                    median_u64(&locked)
                };
                // Some(offset) only when this run is genuinely part of the
                // sweep. `n == 1` has no sweep to be part of: one pair can
                // measure the cycle and says nothing about arrival phase.
                let swept = cycle_hint.filter(|_| run > 1 && n > 1).map(|cycle| {
                    let j = (run - 1) as u64; // 1 ..= n-1
                    cycle * (2 * j - 1) / (2 * (n as u64 - 1))
                });
                let stagger_ms = swept.unwrap_or(0);
                // Derived from whether a sweep offset was APPLIED, never from
                // `stagger_ms > 0` — integer division can floor a legitimate
                // offset to zero at large n, and that sample is still swept.
                let issue_phase = if swept.is_some() { "free" } else { "unknown" };
                if stagger_ms > 0 {
                    println!("  [{run}/{n}] stagger {stagger_ms}ms to break the phase lock");
                    tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
                }

                // ── issue ──────────────────────────────────────────────
                // Free phase: this is the one a customer's sale resembles.
                // Except on run 1, which is `unknown` — see above.
                let unsigned = prepared!(
                    "issue",
                    issue_phase,
                    stagger_ms,
                    run,
                    IComponent::new(&provider, max_epoch)
                        .want_vault_for(me, credit, false)
                        .call_method(component, "issue", args![amount])
                        .then(|b| {
                            b.put_last_instruction_output_on_workspace("card")
                                .create_account_with_bucket(my_key, "card")
                        })
                        .pay_fee(CALL_FEE)
                );
                let sample = timed_call(
                    &mut provider,
                    "issue",
                    issue_phase,
                    stagger_ms,
                    run,
                    cents,
                    unsigned,
                )
                .await;
                println!(
                    "  [{run}/{n}] issue  {issue_phase:<7}finality={}ms total={}ms outcome={}{}",
                    sample.finality_ms,
                    sample.total_ms,
                    sample.outcome,
                    sample
                        .error
                        .as_ref()
                        .map(|e| format!(" err={e}"))
                        .unwrap_or_default()
                );
                let issue_ok = sample.committed;
                samples.push(sample);

                // No point redeeming what was not issued; a failed issue still
                // counts as a finality sample (timeout / reject), but redeem
                // would measure a different failure mode.
                if !issue_ok {
                    continue;
                }

                // ── redeem ─────────────────────────────────────────────
                // Submitted immediately after the issue committed, so this one
                // is phase-locked BY CONSTRUCTION and measures the cycle. Kept
                // deliberately: it is the worst case, and it is also what a
                // second sale rung up straight after the first would see.
                let unsigned = prepared!(
                    "redeem",
                    "locked",
                    0,
                    run,
                    IComponent::new(&provider, max_epoch)
                        .want_vault_for(me, credit, true)
                        .then(|b| {
                            b.call_method(me, "withdraw", args![credit, amount])
                                .put_last_instruction_output_on_workspace("spend")
                        })
                        .call_method(component, "redeem", args![Workspace("spend")])
                        .pay_fee(CALL_FEE)
                );
                let sample =
                    timed_call(&mut provider, "redeem", "locked", 0, run, cents, unsigned).await;
                println!(
                    "  [{run}/{n}] redeem finality={}ms total={}ms outcome={}{}",
                    sample.finality_ms,
                    sample.total_ms,
                    sample.outcome,
                    sample
                        .error
                        .as_ref()
                        .map(|e| format!(" err={e}"))
                        .unwrap_or_default()
                );
                samples.push(sample);
            }

            let issue_summary = summarise("issue", &samples, |s| s.action == "issue");
            let redeem_summary = summarise("redeem", &samples, |s| s.action == "redeem");
            // The cut that actually answers the merchant's question.
            let free_summary = summarise("free_phase", &samples, |s| s.phase == "free");
            let locked_summary = summarise("locked_phase", &samples, |s| s.phase == "locked");
            // Run 1's issue, which could not be staggered. Summarised so it is
            // VISIBLE rather than merely excluded — a sample dropped silently
            // is indistinguishable from a sample never taken, and this one was
            // paid for.
            let unknown_summary = summarise("unknown_phase", &samples, |s| s.phase == "unknown");
            let all_committed: Vec<u64> = samples
                .iter()
                .filter(|s| s.committed)
                .map(|s| s.finality_ms)
                .collect();
            let mut all_sorted = all_committed.clone();
            all_sorted.sort_unstable();

            let measured_utc = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let n_committed = samples.iter().filter(|s| s.committed).count();
            let n_timeout = samples.iter().filter(|s| s.timed_out).count();
            // A sample that neither committed nor timed out: rejected, fee-only,
            // or failed before it ever reached the network.
            let n_other_failure = samples.len() - n_committed - n_timeout;
            // The verdict must not be able to say more than the samples do.
            //
            // The first version branched on `n_committed == 0` and `n_timeout`
            // alone, so a rejected or fee-only sample — which sets NEITHER
            // flag — still produced "every sample committed within the client
            // timeout". A run where every redeem was rejected would have
            // written that sentence, and it would have been false. In a file
            // whose entire product is an honest verdict, that is the defect
            // that matters most, so the incomplete cases are now named.
            let verdict = if n_committed == 0 {
                "NO COMMITS — every sample failed or timed out; finality is unmeasured".to_string()
            } else if n_timeout > 0 || n_other_failure > 0 {
                format!(
                    "PARTIAL — {n_committed} committed, {n_timeout} timed out, \
                     {n_other_failure} failed another way; medians cover the committed samples only"
                )
            } else {
                "MEASURED — every sample committed within the client timeout".to_string()
            };

            let record = serde_json::json!({
                "measured_utc": measured_utc,
                "what": "How long does an Ootle smart-contract call take from submit to finality on esmeralda? OOTLE_SCOPE.md open question 3.",
                "method": format!(
                    "Real gift-card issue+redeem transactions against a published component. \
                     Instant around send_transaction (submit_ms) and watch() (finality_ms). \
                     Client timeout {}s via connect_with_transaction_timeout. \
                     Issuer and holder are the same account. \
                     Pair i of n (i>1) waits (2(i-1)-1)/(2(n-1)) of one measured cycle \
                     before issuing — midpoint offsets over the n-1 pairs that CAN be \
                     staggered, since the stagger is a fraction of a cycle nothing has \
                     measured yet at pair 1. Pair 1's issue is therefore phase `unknown` \
                     and excluded from free_phase. So the ISSUE samples land at spread \
                     points in the consensus cycle (phase `free`) while each REDEEM \
                     follows its issue immediately (phase `locked`). \
                     ⚠ PHASE AND ACTION ARE CONFOUNDED BY THAT DESIGN: every free sample \
                     is an issue and every locked sample is a redeem, so nothing here \
                     separates the two. Read free_phase for what a customer waits and \
                     locked_phase for the cycle length.",
                    TX_TIMEOUT.as_secs()
                ),
                "how_to_read_this": {
                    "free_phase": "A transaction submitted at an arbitrary point in the consensus cycle — what a customer's sale sees, because a customer does not wait for the previous commit before deciding to pay. THIS IS THE MERCHANT-FACING NUMBER.",
                    "locked_phase": "A transaction submitted immediately after a commit. It waits a full cycle every time, so this is the cycle length: the worst case, and the rate at which back-to-back sales can settle.",
                    "unknown_phase": "Pair 1's issue. It cannot be staggered — the stagger is a fraction of a cycle, and at pair 1 no cycle has been measured yet — so its arrival phase is whatever it happened to be. Reported, because it was paid for, and excluded from free_phase, because a sample of unknown phase is not a sample of the sweep.",
                    "why_they_differ": "Ootle commits on a cadence rather than on demand. On 2026-07-31 the first version of this command submitted every transaction back-to-back, so 12 of its 14 samples were locked; they spanned 724 ms (58.2-58.9 s) while the only 2 free-phase samples came back in 35.3 s and 52.0 s. Reporting the pooled median as 'finality latency' overstated the typical wait by roughly 2x.",
                    "why_free_phase_is_not_the_quoted_number": "Read `derived.expected_wait_ms` for the customer-facing figure, not `free_phase.finality_ms_median`. The quoted number is half the measured cycle; the free-phase median is a small swept sample that CONFIRMS that model rather than establishing it. On 2026-07-31 the two agreed to 0.6% — but only because pair 1, then wrongly labelled `free` and let into the median, happened to land at 51.7 s near the top of the range. Had it landed near 5 s the same run would have reported a free-phase median 34% below the half-cycle, with every other number identical. That is why pair 1 is now `unknown` and the sweep runs over the pairs that can carry one.",
                },
                "verdict": verdict,
                "network": "esmeralda",
                "indexer": indexer,
                "client_timeout_s": TX_TIMEOUT.as_secs(),
                // ComponentAddress / ResourceAddress Display already carries
                // the `component_` / `resource_` prefix; do not add another.
                "component": component.to_string(),
                "credit_resource": credit.to_string(),
                "cents_per_action": cents,
                "pairs_requested": n,
                "samples": samples,
                // `derived` is the key `h_docs.py` §9 walks looking for
                // `confidence` / `samples_considered`, so these limits are
                // printed by the sweep on every run rather than waiting in a
                // JSON nobody opens. The epoch-length correction of 2026-07-28
                // is the reason that convention exists: the caveat WAS in the
                // file, in a field no reader of the prose ever met.
                "derived": {
                    "cycle_ms": locked_summary.finality_ms_median,
                    // The model the samples confirm: a transaction waits
                    // (cycle - however far into the cycle it arrived). For
                    // arrivals spread evenly across the cycle that averages
                    // half of it, so THIS is the number to quote for a sale.
                    // Derived from the locked median rather than from the
                    // free-phase median, because the locked samples measure
                    // the cycle directly and a small swept sample estimates
                    // the half-cycle only as well as its offsets are spaced.
                    "expected_wait_ms": locked_summary.finality_ms_median.map(|c| c / 2),
                    "worst_case_ms": locked_summary.finality_ms_median,
                    "samples_considered": n_committed,
                    "confidence": format!(
                        "{} committed samples in one window on {}. The cycle figure is \
                         tight (locked samples agree within a second); the customer-facing \
                         figure is a HALF-CYCLE DERIVED FROM IT, not an independent \
                         measurement of arrival waits. Free-phase samples confirm the model \
                         (stagger + wait tracks one cycle) rather than establishing the \
                         distribution's tail.",
                        n_committed, &measured_utc[..10],
                    ),
                },
                "summary": {
                    "free_phase": free_summary,
                    "locked_phase": locked_summary,
                    "unknown_phase": unknown_summary,
                    "issue": issue_summary,
                    "redeem": redeem_summary,
                    // Kept for continuity with the 2026-07-31 record, and
                    // deliberately last: pooling free and locked samples mixes
                    // two different questions, so it is the least useful figure
                    // here even though it was the headline in the first version.
                    "all_committed_POOLED": {
                        "n": all_sorted.len(),
                        "finality_ms_min": all_sorted.first().copied(),
                        "finality_ms_median": median_u64(&all_sorted),
                        "finality_ms_max": all_sorted.last().copied(),
                        "finality_ms_mean": if all_sorted.is_empty() {
                            None
                        } else {
                            Some(all_sorted.iter().sum::<u64>() as f64 / all_sorted.len() as f64)
                        },
                    }
                },
                "what_this_does_NOT_establish": [
                    "Mainnet finality. Esmeralda only; mainnet is a non-working mode in this repo.",
                    "LocalNet finality. Self-hosted validators are typically faster; this is the public testnet.",
                    "A SLA. One window of N pairs; re-run under load and after stalls.",
                    "That the sale path for a real customer is the same. Issuer==holder here; a deposit into a never-seen account adds create work.",
                    "Indexer honesty beyond the single shipped endpoint.",
                    "The SHAPE of the free-phase distribution. The stagger sweeps the cycle evenly, which is the right way to get a fair MEDIAN out of few samples, but an even sweep is not a random draw and n is small. It says roughly what a sale waits; it does not say how often a sale waits much longer.",
                    "That the cycle is stable. locked_phase measures the cadence during ONE window. A cadence that moves under load would move both numbers, and nothing here watches it over time.",
                    "Anything about a queue. Every sample here is submitted alone. Two tills issuing at once is a different measurement.",
                    "That phase, not action, is what the two figures differ by. PHASE AND ACTION ARE PERFECTLY CONFOUNDED here: every free sample is an `issue` and every locked sample is a `redeem`, because only the issue can be staggered and the redeem must follow it. So the cycle is measured on redeems only and the arrival sweep on issues only, and nothing in this file separates 'submitted at a different point in the cycle' from 'a different transaction'. The two agreed within ~300 ms on 2026-07-31, which bounds the effect without removing the confound. Separating them needs runs that alternate which half of the pair carries the stagger.",
                    "A free-phase REDEEM, which is the sample a merchant most wants. Under the maintainer's 2026-07-31 decision a gift-card redemption is a PAYMENT RAIL transaction, so the customer-facing action is `redeem` — and every redeem here is phase-locked. The quoted expected wait applies to it by the half-cycle model, not by measurement.",
                ],
            });

            // Write FIRST, then canonicalise. `canonicalize` resolves against
            // the filesystem and therefore fails on a path that does not exist
            // yet — so doing it first printed the raw `../..` path on exactly
            // the run where it mattered (the first one) and the tidy path only
            // from the second run onward, which is the opposite of the intent
            // stated when it was written.
            fs::write(&out, serde_json::to_string_pretty(&record)? + "\n")?;
            let out_display = out.canonicalize().unwrap_or_else(|_| out.clone());

            println!();
            println!("{verdict}");
            // Print the two numbers that mean different things, not the pooled
            // one that means neither.
            let line = |label: &str, key: &str| {
                let s = &record["summary"][key];
                if let Some(m) = s["finality_ms_median"].as_u64() {
                    println!(
                        "{label:<12} median={m}ms  min={} max={}  (n={})",
                        s["finality_ms_min"], s["finality_ms_max"], s["n_committed"],
                    );
                }
            };
            line("free phase", "free_phase");
            line("locked", "locked_phase");
            println!(
                "\nfree phase is what a customer waits; locked is the cycle length \
                 (worst case)."
            );
            println!("wrote {}", out_display.display());
        }
        _ => unreachable!("filtered above"),
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// THE CONTROL FOR `check_signing_response`, AND THE ONLY TESTS IN THIS BINARY
//
// `CHARTER.md` §2 rule 4: a guard is only worth what it actually audits, so
// when you write a check, write the control that proves it would still fail on
// the defect it was built for. The defect here is a real one that shipped —
// `submit-request` asked a signature file who had signed it and believed the
// answer — so these are regression tests in the strict sense: rule 7's "attack
// test that becomes a regression test the day its finding closes".
//
// **THE FIXTURES ARE REAL AND THEY ARE NOT SECRETS.** `tests/fixtures/` holds
// two requests composed against the live esmeralda component on 2026-08-15 and
// one honest signature over the second of them. The module comment above
// `SigningRequest` says why a request can be checked into a repository at all:
// it is an unsigned transaction and two public keys, it lets nobody spend
// anything, and without the member's secret key it cannot be signed. The
// signature likewise authorises exactly one transaction that has already been
// superseded.
//
//   cd ootle/loyalty && cargo test     the contract
//   cd ootle/toolkit && cargo test     this
#[cfg(test)]
mod tests {
    // ---- the payment window --------------------------------------------
    //
    // WHY A SOURCE-LEVEL TEST SITS BESIDE THE UNIT TESTS. The unit tests below
    // prove the RULE. They would all stay green if somebody deleted the two
    // `refuse_if_window_closed()?` calls, and then the rule would be correct
    // and never consulted -- which is the shape of defect this repository
    // keeps paying for. So one test reads this file and asserts the call is
    // still there, in both payment verbs, immediately before the irreversible
    // `send_transaction`.

    #[test]
    fn window_refusal_is_silent_when_no_deadline_was_given() {
        assert!(window_refusal(None, 1_000).is_none());
    }

    #[test]
    fn window_refusal_is_silent_while_the_window_is_open() {
        assert!(window_refusal(Some(1_000), 999).is_none());
    }

    #[test]
    fn window_refusal_fires_on_the_deadline_itself() {
        // The adapters credit a payment finalising AT the expiry, but this is
        // submission, not finalisation: at the deadline there is no time left
        // for the transaction to land, so equality refuses.
        assert!(window_refusal(Some(1_000), 1_000).is_some());
    }

    #[test]
    fn window_refusal_says_how_late_it_is() {
        let reason = window_refusal(Some(1_000), 1_042).expect("must refuse");
        assert!(reason.contains("42s ago"), "{reason}");
        assert!(reason.contains("Nothing \
             was submitted") || reason.contains("Nothing"), "{reason}");
    }

    #[test]
    fn both_payment_verbs_check_the_window_before_submitting() {
        // Only the code ABOVE the test module: this test's own body contains
        // the literal it searches for, and counting those made it read 5.
        let whole = include_str!("main.rs");
        let source = whole
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(whole);
        let guarded = source
            .match_indices("refuse_if_window_closed()?;")
            .count();
        assert_eq!(
            guarded, 2,
            "expected the window check in BOTH `devbench pay` and `devbench \
             pay-sale`, found {guarded}. A rule that is never consulted is not \
             a rule."
        );
        // And each one must come immediately before a submission, with nothing
        // network-capable in between.
        for (at, _) in source.match_indices("refuse_if_window_closed()?;") {
            let after = &source[at..];
            let submit = after
                .find("send_transaction")
                .expect("a window check with no submission after it");
            let between = &after["refuse_if_window_closed()?;".len()..submit];
            // EXACT, not `starts_with`. A prefix test would accept an
            // inserted `let pending = network_operation().await?;` sitting
            // between the check and the real submission -- which is precisely
            // the gap the check exists to close.
            let normalised = between.split_whitespace().collect::<Vec<_>>().join(" ");
            assert_eq!(
                normalised, "let pending = provider.",
                "nothing may sit between the window check and send_transaction; \
                 found: {between:?}"
            );
        }
    }

    use super::*;

    /// HOW TO REGENERATE THESE, because the previous set died silently.
    ///
    /// They were composed under `ootle-rs` 0.16 and stopped decoding when the
    /// toolkit moved to 0.21 on 2026-08-30 to follow a wire format esmeralda
    /// had already moved to. The three tests below then failed for a day and
    /// nothing reported it, because `harnesses/run_all.py` does not run
    /// `cargo test`. The current set was made on 2026-08-31 against a live
    /// esmeralda:
    ///
    /// ```text
    /// pocket address                                   # a key that is not the merchant's
    /// toolkit payments pay <component> 5000000 <ref> \
    ///     --member <pubkey> --account <account> --compose request_member3.json
    /// pocket sign request_member3.json sig_from_key3.json
    /// # and a SECOND request naming a DIFFERENT member key, for the forgery tests:
    /// toolkit payments pay <component> 5000000 <other-ref> \
    ///     --member <other-pubkey> --account <other-account> --compose request_member2.json
    /// ```
    ///
    /// The two requests must name different member keys AND carry different
    /// transactions; `a_signature_over_another_transaction_is_refused` swaps
    /// one into the other and would prove nothing if they matched.
    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .expect("fixture is checked in beside this file")
    }

    fn request(name: &str) -> SigningRequest {
        serde_json::from_str(&fixture(name)).expect("a composed request")
    }

    fn response(name: &str) -> SigningResponse {
        serde_json::from_str(&fixture(name)).expect("a signature")
    }

    fn unsigned_of(request: &SigningRequest) -> UnsignedTransaction {
        tari_bor::decode(&from_hex(&request.unsigned_cbor).expect("hex"))
            .expect("the composed transaction decodes")
    }

    /// The honest path, first — because a check that refuses everything would
    /// pass every test below and be worse than the defect it replaced.
    #[test]
    fn an_honest_signature_is_accepted() {
        let request = request("request_member3.json");
        let response = response("sig_from_key3.json");
        let signature = check_signing_response(&request, &response, &unsigned_of(&request))
            .expect("the signature bench key 3 produced over bench key 3's request");
        assert_eq!(pubkey_hex(signature.public_key()), request.member_key);
    }

    /// THE DEFECT, EXACTLY AS IT WAS EXPLOITED. One field edited in the
    /// response — the label — and the signature bytes left alone. Against the
    /// code as it shipped this passed, and `submit-request` printed
    /// `signed by 48d0…` about a signature produced by `2a29…`.
    #[test]
    fn a_relabelled_signature_is_refused() {
        let request = request("request_member2.json");
        let mut response = response("sig_from_key3.json");
        assert_ne!(response.member_key, request.member_key, "the fixtures differ");

        // The forgery: claim to be the key the request asks for.
        response.member_key = request.member_key.clone();

        let refusal = check_signing_response(&request, &response, &unsigned_of(&request))
            .expect_err("a signature from another key must not be accepted");
        assert!(
            refusal.contains("the signature ITSELF was produced by"),
            "the refusal has to name what it found, not just say no: {refusal}"
        );
        // NAMES BOTH KEYS. An operator holding two files needs to know which
        // one is wrong, and a refusal that says only "mismatch" sends them to
        // read a chain.
        // The key that REALLY signed, and the key the forgery claims.
        assert!(refusal.contains("b065b7a3f28a87074cb90d3b27114648d029b39624d111ae74b5368f4e393e7d"));
        assert!(refusal.contains("2a29b127451db6a848def376f0330cd0561abbdb6f2d4ad305c77a31fb5d9126"));
    }

    /// A SIGNATURE LIFTED ONTO A DIFFERENT TRANSACTION. Key 3 really did sign,
    /// really is who the request names — and signed something else. This is
    /// the case the label check cannot reach even in principle, which is why
    /// the Schnorr verification is not redundant with it.
    #[test]
    fn a_signature_over_another_transaction_is_refused() {
        // Request 3's identity fields with request 2's transaction: the shape
        // a tampered request takes after the customer has already signed.
        let mut request = request("request_member3.json");
        request.unsigned_cbor = self::request("request_member2.json").unsigned_cbor;

        let refusal = check_signing_response(
            &request,
            &response("sig_from_key3.json"),
            &unsigned_of(&request),
        )
        .expect_err("a valid signature over the WRONG transaction must not be accepted");
        assert!(
            refusal.contains("does not verify against this transaction"),
            "and it must say which of the two things is wrong: {refusal}"
        );
    }

    /// `--compose` with its filename forgotten used to return `None`, leave
    /// the flag in argv, and drop the run into the dev-bench path that MINTS
    /// the counterparty's key. The refusal is the fix; this is its control.
    #[test]
    fn a_flag_without_a_value_is_refused_rather_than_ignored() {
        let mut argv: Vec<String> =
            ["toolkit", "loyalty", "enrol", "c", "r", "v", "--compose"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let refused = take_flag(&mut argv, "--compose").expect_err("no value was given");
        assert!(refused.contains("needs a value"));
        assert!(
            argv.iter().any(|a| a == "--compose"),
            "and nothing was consumed, so no later parse can read past it"
        );

        // THE CONTROL: the same call with a value still works, and still
        // leaves the positional arguments where every other verb expects them.
        let mut argv: Vec<String> =
            ["toolkit", "loyalty", "enrol", "c", "r", "v", "--compose", "out.json"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(
            take_flag(&mut argv, "--compose").expect("valid"),
            Some("out.json".to_string())
        );
        assert_eq!(argv, ["toolkit", "loyalty", "enrol", "c", "r", "v"]);
    }
}
