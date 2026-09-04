# Catflix

A shop for cat portraits, served from **Freenet**, bought with **XTR on the
Tari Ootle**. Nine encrypted portraits, nine free posters, and a paywall that
is a real cryptographic boundary rather than a hidden `<div>`.

**Order one portrait for 1 XTR and it is yours, kept.** Or rent all nine for
30 days for 7.50 XTR. Each portrait has its own key, so buying one hands over
one — the others stay ciphertext you are welcome to download.

```
poster  (plaintext, in the web container)   →  anyone
portrait(AES-GCM ciphertext, same directory)→  anyone can download, nobody can open
that portrait's key                         →  sealed to the buyer's X25519 key,
                                               written to a Freenet contract only after
                                               a payment NAMING THAT KEY AND THAT PORTRAIT
                                               lands on-chain
```

## Use it

```bash
freenet local --ws-api-address 127.0.0.1   # once, in its own terminal
./catflix up                               # build + publish; prints the URL
./catflix serve                            # the seller, in its own terminal
./catflix order t3                         # buy one portrait, no browser needed
```

`./catflix order` does from a terminal exactly what the page does in a browser:
mints a keypair, builds a reference, pays it, waits for the seller, opens the
envelope, and writes the decrypted portrait into `unlocked/`. It exists because
a published Freenet site cannot be scripted — see below.

In the browser: **Add to basket** on any card, then one **Order** for the lot —
a basket of three is one reference, one payment, three portraits. An order you
cannot pay has **"no wallet? let the house pay"**, which puts your reference
into a second Freenet contract that `./catflix serve` sweeps.

Because the published page has no storage, it shows a **recovery code** after
each order. That code is the purchase. Paste it into *Restore a key* to get the
portraits back on any machine.

| command | |
|---|---|
| `./catflix up` | build the contracts and the site, publish all three, print the URL |
| `./catflix serve` | watch the chain, issue entitlements, pay for covered requests |
| `./catflix order <sku>` | mint, pay and unlock without a browser (`t0`…`t8`, or `all`) |
| `./catflix pay <ref>` | pay a reference the browser produced |
| `./catflix wallet` | mint and fund the demo payer |
| `./catflix status` | who bought what |
| `./catflix check` | every gate |
| `./catflix url` | where the site is |

---

## What is proven, and how

Everything below was executed against a live Freenet node and the live
esmeralda testnet on 2026-09-02. Nothing here is a plan.

| claim | evidence |
|---|---|
| **a basket works with storage blocked** | two portraits added, ordered as `m17` in one payment of 2.00 XTR — tx `75fbc4e1…52dabf6` — both unlocked, seven still for sale |
| a recovery code survives losing everything | reload wiped the page to `nothing unlocked`; pasting the code restored `2 of 9 unlocked · 2 kept` |
| the page charges what the seller demands | `tests/test_pricing.js` runs the page's own tariff against the gatekeeper's `price_of` for 9 SKU shapes |
| **one portrait can be ordered and unlocked** | `./catflix order t3` → tx `64b24865…0eb1b5c`, 1,000,000 µXTR → entitlement seq 1 opening exactly **one** portrait, decrypted to a 24,910-byte WEBP |
| ordering one hands over **only** one | browser order of `t4` → tx `7e2d6e2a…1379162` → `The Red Dot` revealed, badge `1 of 9 unlocked · 1 kept`, **8 cards still locked and for sale** |
| a second purchase does not erase the first | then `t0` → tx `f6931da8…0bc0fca1` → `2 of 9 unlocked · 2 kept`, both revealed, 7 still for sale |
| a visitor with **no wallet at all** can buy | "let the house pay" → reference into the queue contract → the sweep read the SKU, paid the right price, tx `5092b4a7…0a3cef4d` → `Three A.M.` unlocked |
| a replayed older issuance cannot displace a newer one | contract accepted a genuine `seq 2` envelope over a live `seq 5` and kept **5** |
| the gatekeeper ignores other people's traffic | credited 3, **ignored 7** real payments to the same shared component (AzerothCore till references, and this project's own pre-SKU ones) |
| a forged entitlement is refused | contract rejected an envelope signed by another key: *"an entitlement is not signed by this contract's gatekeeper"* |
| a tampered entitlement is refused | the genuine envelope with an edited expiry — same refusal, state unchanged |
| an envelope relabelled to another subscriber is refused | same refusal |
| a state out of canonical order is refused | same refusal |
| the refusals are not just "every push fails" | a **control** pushes a genuine envelope in the same run and asserts it lands |
| only the buyer can open it | a second keypair gets `InvalidTag` |
| the merge obeys the network's laws | `fdev verify-merge`: **199 cases, 198 held, 0 violations, 1 inconclusive** (entitlements), 15/15 (queue) |
| paying twice for one request is impossible | second `cover` sweep over the same queue: *"nothing in the queue that has not already been paid"* |

The one inconclusive merge case is *"no delta path to compare against"*, and it
is a direct consequence of a deliberate optimisation: `get_state_delta` returns
an **empty** byte string when the peer is already current, rather than a
25-byte empty register. With no delta there is nothing for the verifier to
compare, so it reaches no verdict on that pair. It is not a finding, and it is
recorded here so nobody spends an afternoon on it.

### The claim that was wrong

An earlier version of this file said the published copy's buttons must work
because its bundle is byte-identical to the one everything was tested against.
**That inference was wrong, and the buttons did not work.** The bundle matched;
the *environment* did not.

Freenet serves a web container in an iframe sandboxed without
`allow-same-origin`, which gives it an **opaque origin** — and in an opaque
origin `localStorage`, `sessionStorage` and `indexedDB` all throw
`SecurityError`. Measured in a harness carrying Freenet's exact sandbox
attributes, not inferred. The order handler wrote the new keypair straight to
`localStorage`, so every click threw, the promise rejected into nothing, and
the button looked dead.

Two things came out of it. The page now detects that it cannot save and says
so, and after an order it shows a **recovery code** — because with no storage
that code is the only copy of the purchase. And every test since runs against a
copy with storage deliberately blocked, which is the environment that matters.

Run the gates yourself:

```bash
./catflix check     # 66 unit refusals, the merge law, 12 attacks on the live contract
```

---

## The three pieces

### 1. `contract/` — the entitlement register

A Rust/WASM Freenet contract. Its state is a **join-semilattice**: entitlements
keyed by subscriber, and where two claim the same subscriber the join takes the
higher **issuance sequence** (ties broken on signature bytes, so every peer
picks the same one).

The join key was the expiry until portraits became separately purchasable, and
then it stopped working: buying two portraits outright produces two envelopes
with the *same* perpetual expiry, so the join would tie and fall back to
signature bytes — and a buyer could lose a portrait they had paid for. `seq`
rises on every issuance and every issuance carries the buyer's **whole** set of
grants, so "newest wins" is a superset rather than a replacement.

The gatekeeper's Ed25519 public key is the contract's **parameters**, and
parameters are part of the address. Everything in state must carry a signature
by that key.

### 2. `gatekeeper/` — the seller

Watches `Payments.PaymentReceived` on the deployed Ootle component, credits
payments whose reference it recognises, and writes sealed envelopes into the
contract. Five obligations, each taken from a defect somebody already paid for
— see the module docstring; the sharpest is that **price is enforced here or
nowhere**, because the payment component checks `amount > 0` and deliberately
nothing else.

### 3. `site/` + `ui/` — the buyer

A dependency-free page. X25519, Ed25519, HKDF and AES-GCM are all native
WebCrypto on the Freenet origin (verified in Chrome 151), so the only bundled
library is the Freenet SDK itself.

A **fresh keypair per order**: the reference must carry the public key in full
(a hash cannot be sealed to), which puts it on a public ledger — so reusing one
key would let an observer stitch a customer's purchases together. The page
therefore holds a keyring and opens **every** envelope addressed to any key in
it, which is what makes two separately-bought portraits both appear. The cost
is stated on the page: the keyring *is* the purchase.

### `contract-requests/` — how a sandboxed page asks for help

A published web container is sealed: no parent page, no operator, no tooling
can read inside it. So "let the house pay for me" cannot be an HTTP call — the
page writes its reference into a second, unsigned, grow-only contract and the
operator reads it from the other side. Anyone may append; the house decides
what it pays, and the cap is the protection.

---

## Running it

```bash
python3 gatekeeper/gatekeeper.py init          # mint the signing key (once)
./build.sh                                     # contracts, merge gate, catalogue, site
fdev website publish ./site --key catflix      # the UI
fdev execute put --code contract/target/wasm32-unknown-unknown/release/catflix_entitlements.wasm \
    --parameters keys/params.bin contract --state keys/initial-state.json
python3 gatekeeper/gatekeeper.py watch --contract <key>
python3 gatekeeper/gatekeeper.py cover --queue <queue key> --max 2
python3 gatekeeper/gatekeeper.py status
```

`build.sh` derives every address it writes into `config.json` rather than
having one typed, because a site published against a contract key that has
since moved looks exactly like a site nobody has ever paid.

**To debug the UI**, add `"node": "127.0.0.1:7509"` to `site/config.json` and
serve the directory over plain HTTP. This is the only way to see its console.

---

## Behind a domain

Live at **https://<the catflix hostname>/** — a Cloudflare Tunnel to a
Freenet node on this machine, for people who do not run a node themselves.

```
<the catflix hostname>
        │  cloudflared, outbound only — no port is opened on this host
        ├── /v1/contract/web/<key>/*  ─┐
        │   /v1/contract/command       ├─► 127.0.0.1:7510   throwaway node
        └── everything else ──────────►   127.0.0.1:7511   redirect to the site
```

**A throwaway node, not the working one.** `freenet --ws-api-address` says of
this port: *"anything that can reach this address and port can read and modify
your contract state, identities and keys."* The app needs that socket, so the
node it belongs to is one holding nothing but public cat ciphertext and two
self-validating contracts. The working node on 7509 stays off the internet.
What an exposed API risks is the node — not the site, which is signed by a key
that never enters a node, and not entitlements, which are refused unless the
gatekeeper signed them.

**Only two paths are proxied.** The node serves its **admin dashboard** at `/`.
Sending a hostname's root at the node would publish the control surface, so
everything outside those two paths goes to `frontdoor.py`, twenty lines that
302 to the site and hold nothing.

**The seller must serve every node a reader might use.** `--node-port` is
repeatable and entitlements are pushed to all of them; the request queue is
read from all and unioned. Issuing to one node while somebody reads from
another leaves a paying customer looking at a locked page:

```bash
./catflix serve --node-port 7509 --node-port 7510 --front-door 7511
```

### Two things that broke, both silent

**`ws://` hardcoded.** A browser blocks a plaintext WebSocket from an `https`
page as mixed content, so the page would load, render the entire catalogue, and
never connect. The scheme is derived from `location.protocol` now.

**The node refuses a WebSocket carrying an `Origin` it does not know.** With
the reverse proxy in place the upgrade returned `403 WebSocket connections from
this origin are not allowed`, while a client sending *no* Origin got `101` — so
every tool said the socket was fine and only a browser failed. `--allowed-host`
is the flag for it, and Freenet's own help says why it exists: *"that is a
Host-header allowlist, and it works on loopback, where a same-host reverse
proxy lives."*

```bash
freenet local --ws-api-port 7510 --allowed-host <the catflix hostname> \
    --config-dir ~/.config/freenet-public --data-dir ~/.local/share/freenet-public
```

### What the domain costs

A visitor arriving this way is trusting **this machine** — its uptime, its
operator, and a DNS record that can be pulled. The README's claim that this
needs *no domain, no TLS certificate, no host* stops being true for them; it
stays true for anyone who opens the same contract address on their own node,
which is the version that survives this machine being switched off.

## You cannot automate a Freenet web container

A node serves every web container inside an iframe (`?__sandbox=1`) carrying
`allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox
allow-downloads allow-modals` — and notably **not** `allow-same-origin`. The
consequences are absolute and were measured one at a time:

| attempted | result |
|---|---|
| read the frame's DOM from the parent | `contentDocument` is `null` |
| read its console | the console reader returns nothing |
| read its accessibility tree | "only a generic element with no content" |
| synthetic click on a control inside it | no event fires |
| `Tab` into it | focus stays on the parent `body` |

The click result is the one worth isolating, because it looks exactly like a
broken button. It is not. On a plain local page with no Freenet in sight:

- a click on a **top-level** page lands correctly (calibrated: a click at
  screenshot (376, 232) arrived at CSS (465, 287), on target)
- the same click into an **iframe** with Freenet's exact sandbox attribute
  fires nothing
- and — the control that settles it — the same click into an iframe with **no
  sandbox attribute at all** also fires nothing

So it is iframes, not Freenet's sandbox, and certainly not this app. But since
Freenet serves every container in one, the practical rule stands: **a published
Freenet app can only be driven by a human.**

That is why `config.json` accepts a `node` key. Point it at your node, serve
`site/` over plain HTTP, and the identical bundle becomes scriptable and has a
console. Every interactive claim in the table above was proven that way, and
the bundles were then compared by sha256.

## Two directories, and only one of them matters

```
keys/   losing any of this cannot be undone
        gatekeeper.ed25519   its PUBLIC half is the contract's address, so
                             replacing it abandons every entitlement ever sold
        content-titles.json  lose these and every portrait sold becomes
                             ciphertext to the people who bought it
        ledger.sqlite3       what was sold, to whom, and what is undelivered
        order-*.json         purchases made by `catflix order` — these are keys

run/    regenerated on the next sweep; delete freely
```

They were one directory until somebody had to be told which of twenty-five
files were safe to delete — which is a question nobody should have to ask about
a directory containing a private key. `run/` is gitignored; so is `keys/`.

## Only one seller

`catflix serve` takes an exclusive lock on `run/serve.lock` and refuses to
start beside another. Two of them ran side by side here for several hours and
it was invisible: both printed the same reassuring lines. They share one SQLite
ledger and both mint the `seq` the entitlement contract joins on, so the second
is a race over who issues what. Crediting survives it — the event id is a
primary key — but issuance does not, and the failure would look like a
customer's purchase quietly never arriving.

## Five ways this broke, all of them quiet

Each cost real time and each is the same shape: a check that lived in one place
while the thing it checked was owned by another.

**A shape check in the wrong contract.** The request queue validated that a
reference had *three* dot-separated parts. When the SKU was added it had four.
The queue then refused every reference the site produced — and the refusal
surfaced as the "let the house pay" button hanging forever, its promise neither
resolved nor rejected, with the visitor told nothing. The queue now checks the
size, and the gatekeeper that actually owns the format checks the meaning.

**Concurrent calls to the node get their answers swapped.** The SDK says
requests are delivered FIFO and mismatch if they overlap; that is not
theoretical. A background poll's `get` landed on top of the queue `update` and
took its response. Every call now goes through one promise chain, and the one
user-facing call has a timeout so a hang becomes a sentence rather than a dead
button.

**A timeout tuned against a warm contract.** The first write to a
freshly-published contract took about fifteen seconds, because the node has to
fetch the contract before it can run the update. A 20-second limit tripped on
exactly the case it was meant to survive. It is 45 now, measured rather than
guessed.

**Storage that is not there.** Covered above: the whole buy path died on a
`localStorage` write in an origin that has none, and nothing said so. Every
call that can fail in a click handler now reports rather than rejecting into
silence.

**One tariff, two implementations.** The page priced a basket of three at the
cost of one while the gatekeeper demanded three — a customer following the page
would have underpaid, been refused, and left the money in a component that
cannot refund it. There is now one `ui/pricing.js`, and `check.sh` runs it
against the gatekeeper's own `price_of` for every SKU shape.

## What this does NOT enforce

This design was put through an adversarial review before it was built
(`tools/.codex-answers/20260903T012604Z-against-595146.md`), which returned a
verdict of *reject*. Most of what it found is fixed and proven above. Three
findings are not fixable and are stated here rather than hoped over.

**1. After one buyer decrypts, that portrait's paywall is over.** They hold its
key and its pixels and can publish either. There is no cryptographic answer —
only DRM, which this is not. What this *does* enforce is payment before **first
delivery to an honest customer**, which is what a paywall is. Per-title keys do
bound the damage: a leaked key opens one portrait, not the shop.

**2. Expiry gates future deliveries, not past ones.** A key already handed over
cannot be revoked by a date. Key rotation per epoch bounds the blast radius of
a leak to one epoch; it does not undo one.

**3. The gatekeeper is the service.** It decides whether a payment was enough,
who gets access, and for how long. Freenet verifies only that it signed the
result. Steal its key and you can mint access; and because its public key is
the contract's parameters, **it cannot be rotated** — a different key is a
different contract at a different address, reproduced here with
`fdev execute get-contract-id`. Fixing that needs a root key in parameters and
a revocable operating key in state, which needs tombstones, which is the same
unsolved problem as pruning expired entries. Not built.

The narrower claim that survives, and is the reason any of this is on Freenet:

> **The gatekeeper is needed to sell. It is never needed to serve.**

Kill it and every existing subscriber keeps working — the envelope is already
replicated and the ciphertext is already in the container. No domain, no TLS
certificate, no host, no uptime. An HTTPS key service cannot say that.

Two more things that are true and easy to overstate:

- **esmeralda is a faucet testnet.** Test XTR is free, so this demonstrates
  payment plumbing, not an economic barrier.
- **The register grows forever.** Entitlements are never removed, because
  removal from a replicated set needs tombstones. An envelope grows with the
  number of portraits its owner has bought — about 120 bytes each.
- **A ledger from before per-title ordering cannot be opened.** References had
  three parts and bundles were keyed by epoch. `open_ledger` detects the old
  schema and tells you to archive it, rather than failing later in the middle
  of crediting somebody's payment.
