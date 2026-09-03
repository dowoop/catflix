/**
 * Catflix — the subscriber's half.
 *
 * Everything secret happens here, in the browser, and nothing secret ever
 * leaves it. The page mints its own X25519 keypair, hands only the PUBLIC
 * half to the payment reference, and opens the envelope the gatekeeper seals
 * back to it. There is no login, no account and no server to have one on.
 *
 * ## A fresh keypair per order, deliberately
 *
 * The payment reference carries the public key in full, because a gatekeeper
 * that only saw a hash of it would have nothing to seal a bundle to. That has
 * a cost: the reference is on a public ledger, so anyone can see that this key
 * bought a subscription and when.
 *
 * Reusing one key across renewals would let an observer stitch those purchases
 * into one customer's history. So every order mints a NEW keypair and the
 * browser keeps a keyring; two renewals by the same person share nothing on
 * the chain. The cost is that the keyring is the subscription — clear the
 * browser's storage and the entitlement is still in Freenet, still valid, and
 * no longer openable by anybody. That is stated on the page rather than
 * discovered later.
 */

import { priceOf as priceRule } from "./pricing.js";
import { FreenetWsApi, ContractKey, GetRequest, SubscribeRequest, UpdateRequest,
         UpdateData, UpdateDataType, DeltaUpdate } from "@freenetorg/freenet-stdlib";

const SIGNING_INFO = "catflix-envelope-v1";
const TITLE_AAD = "catflix-title-v1";
const HKDF_SALT = new Uint8Array(32);
const KEYRING = "catflix.keyring.v1";

const enc = new TextEncoder();
const $ = (id) => document.getElementById(id);

const b64 = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (text) => {
  const s = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

/**
 * Storage, and why there may not be any.
 *
 * A published Freenet web container runs in an iframe sandboxed WITHOUT
 * `allow-same-origin`, which gives it an opaque origin. In an opaque origin
 * `localStorage`, `sessionStorage` and `indexedDB` all throw `SecurityError` —
 * measured, not assumed. So the page cannot save anything, and the first
 * version of this file called `localStorage.setItem` unguarded inside the
 * Order handler: every click threw, the promise rejected into nothing, and the
 * button appeared dead. That is the bug this wrapper exists to remove.
 *
 * Where storage works the keyring persists. Where it does not, the page keeps
 * keys in memory and says so — loudly, because the key IS the purchase and a
 * closed tab would otherwise take it.
 */
const store = {
  available: (() => {
    try { localStorage.setItem("catflix.probe", "1"); localStorage.removeItem("catflix.probe"); return true; }
    catch { return false; }
  })(),
  read(key) {
    if (!this.available) return null;
    try { return localStorage.getItem(key); } catch { return null; }
  },
  write(key, value) {
    if (!this.available) return false;
    try { localStorage.setItem(key, value); return true; } catch { return false; }
  },
  clear(key) { try { localStorage.removeItem(key); } catch { /* nothing to clear */ } },
};

const state = {
  catalog: null,
  keyring: [],
  cart: new Set(),   // title skus chosen but not yet ordered
  grants: {},        // title id -> { key: CryptoKey, until: unix seconds, 0 = kept }
  entitlement: null, // the winning entitlement record
  decrypted: {},     // title id -> object URL
  config: null,
};

/** A key as a copyable code, so a page that cannot save can still be saved. */
function codeFor(record) {
  return `${record.priv}.${record.pub}`;
}

/** Take a code back. Returns the record, or throws. */
async function importCode(text) {
  const [privText, pubText] = text.trim().split(".");
  if (!privText || !pubText) throw new Error("that is not a Catflix key code");
  const priv = await crypto.subtle.importKey(
    "pkcs8", unb64(privText), { name: "X25519" }, true, ["deriveBits"]);
  if (state.keyring.some((k) => k.pub === pubText)) return null;
  const record = { pub: pubText, priv: privText, ref: "", sku: "", created: Date.now() };
  let stored = [];
  try { stored = JSON.parse(store.read(KEYRING) || "[]"); } catch { stored = []; }
  stored.push(record);
  store.write(KEYRING, JSON.stringify(stored));
  state.keyring.push({ pub: pubText, priv, ref: "", sku: "", created: record.created });
  return record;
}

/** Is this specific portrait open to us right now? */
function granted(titleId) {
  const grant = state.grants[titleId];
  if (!grant) return false;
  return grant.until === 0 || grant.until * 1000 > Date.now();
}

// ---------------------------------------------------------------------------
// the keyring
// ---------------------------------------------------------------------------

async function loadKeyring() {
  let stored = [];
  try { stored = JSON.parse(store.read(KEYRING) || "[]"); } catch { stored = []; }
  const keys = [];
  for (const record of stored) {
    try {
      const priv = await crypto.subtle.importKey(
        "pkcs8", unb64(record.priv), { name: "X25519" }, true, ["deriveBits"]);
      keys.push({ pub: record.pub, priv, ref: record.ref, sku: record.sku, created: record.created });
    } catch { /* a key this browser can no longer import is not recoverable */ }
  }
  return keys;
}

async function mintOrder(sku) {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const priv = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  // The freshness suffix. Without it a renewal reuses its predecessor's
  // reference, and this project has already measured what a repeated
  // reference does to a ledger that gets restored from a backup.
  const suffix = b64(crypto.getRandomValues(new Uint8Array(9)));
  // The SKU rides in the reference because the money has to say what it is
  // buying. Inferring the order from the amount is the exact defect the
  // payment component was built to remove.
  const ref = `CF1.${b64(pub)}.${sku}.${suffix}`;

  const record = { pub: b64(pub), priv: b64(priv), ref, sku, created: Date.now() };
  let stored = [];
  try { stored = JSON.parse(store.read(KEYRING) || "[]"); } catch { stored = []; }
  stored.push(record);
  // May be a no-op. That is expected in a published container and is why
  // `renderRecovery` puts the code on screen instead.
  store.write(KEYRING, JSON.stringify(stored));
  state.keyring.push({ pub: record.pub, priv: pair.privateKey, ref, sku, created: record.created });
  return record;
}

// ---------------------------------------------------------------------------
// opening an envelope
// ---------------------------------------------------------------------------

async function unseal(entitlement, privateKey) {
  const eph = unb64(entitlement.eph);
  const sub = unb64(entitlement.sub);
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "X25519", public: await crypto.subtle.importKey("raw", eph, { name: "X25519" }, false, []) },
    privateKey, 256));

  // The same refusal the gatekeeper makes when sealing. An all-zero shared
  // secret is a constant every reader can derive, so a bundle "encrypted"
  // under it is public. Checking on both ends costs nothing and means neither
  // end is trusting the other to have checked.
  if (shared.every((byte) => byte === 0)) throw new Error("all-zero shared secret");

  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: concat(enc.encode(SIGNING_INFO), eph, sub) },
    ikm, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(entitlement.nonce), additionalData: concat(enc.encode(SIGNING_INFO), sub, eph) },
    key, unb64(entitlement.sealed));
  return JSON.parse(new TextDecoder().decode(plain));
}

/**
 * Open every envelope in the register that belongs to a key we hold.
 *
 * EVERY one, not the best one. The keyring holds a fresh keypair per order --
 * that is what stops an observer linking one person's purchases on a public
 * ledger -- so a customer who bought two portraits separately has two
 * entitlements under two different keys, and taking only the "best" would
 * silently drop one of them.
 */
async function adoptEntitlements(register) {
  const mine = new Map(state.keyring.map((k) => [k.pub, k]));
  let adopted = false;

  for (const entitlement of register.entitlements || []) {
    const held = mine.get(entitlement.sub);
    if (!held) continue;
    let bundle;
    try { bundle = await unseal(entitlement, held.priv); } catch { continue; }

    for (const [titleId, grant] of Object.entries(bundle.grants || {})) {
      const existing = state.grants[titleId];
      // Keep the stronger claim: kept (until 0) beats any deadline, and a
      // later deadline beats an earlier one.
      if (existing && (existing.until === 0 ||
          (grant.until !== 0 && grant.until <= existing.until))) continue;
      state.grants[titleId] = {
        key: await crypto.subtle.importKey("raw", unb64(grant.key), { name: "AES-GCM" }, false, ["decrypt"]),
        until: grant.until,
      };
    }
    if (!state.entitlement || entitlement.seq > state.entitlement.seq) state.entitlement = entitlement;
    adopted = true;
  }
  return adopted;
}

// ---------------------------------------------------------------------------
// decrypting a title
// ---------------------------------------------------------------------------

async function reveal(title) {
  if (state.decrypted[title.id]) return state.decrypted[title.id];
  const grant = state.grants[title.id];
  if (!grant) throw new Error("no key for this portrait");
  const key = grant.key;

  const response = await fetch(title.enc);
  const ciphertext = await response.arrayBuffer();
  const epochBytes = new Uint8Array(4);
  new DataView(epochBytes.buffer).setUint32(0, title.epoch, false);
  const aad = concat(enc.encode(TITLE_AAD), enc.encode(title.id), epochBytes);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(title.nonce), additionalData: aad }, key, ciphertext);
  const url = URL.createObjectURL(new Blob([plain], { type: "image/webp" }));
  state.decrypted[title.id] = url;
  return url;
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/** How many of the nine are open to us. */
function openCount() {
  return state.catalog.titles.filter((t) => granted(t.id)).length;
}

function renderStatus(text, tone = "") {
  const el = $("status");
  el.textContent = text;
  el.className = `status ${tone}`;
}

function renderBadge() {
  const badge = $("badge");
  const open = openCount();
  const total = state.catalog.titles.length;
  if (open === 0) {
    badge.textContent = "nothing unlocked";
    badge.className = "badge";
  } else {
    const kept = state.catalog.titles.filter((t) => state.grants[t.id]?.until === 0).length;
    badge.textContent = open === total
      ? `all ${total} unlocked${kept ? ` · ${kept} kept` : ""}`
      : `${open} of ${total} unlocked${kept ? ` · ${kept} kept` : ""}`;
    badge.className = "badge live";
  }
}

function renderGrid() {
  const grid = $("grid");
  grid.innerHTML = "";
  const price = (state.config.pricePerTitle / 1e6).toFixed(2);
  for (const title of state.catalog.titles) {
    const open = granted(title.id);
    const kept = state.grants[title.id]?.until === 0;
    const card = document.createElement("article");
    card.className = "card" + (open ? " unlocked" : "");
    card.innerHTML = `
      <div class="art">
        <img alt="${title.title}" src="${title.poster}" loading="lazy">
        <span class="lock" aria-hidden="true">${open ? (kept ? "★" : "") : "🔒"}</span>
      </div>
      <h3>${title.title}</h3>
      <p class="meta">${title.year} · ${title.runtime} · ${(title.bytes / 1024).toFixed(0)} KiB sealed</p>
      <p class="syn">${title.synopsis}</p>
      <div class="buy"></div>`;
    const slot = card.querySelector(".buy");
    if (open) {
      slot.innerHTML = `<span class="owned">${kept ? "yours, kept" : "unlocked"}</span>`;
      const img = card.querySelector("img");
      reveal(title)
        .then((url) => { img.src = url; card.classList.add("revealed"); })
        .catch((e) => {
          card.classList.add("broken");
          card.querySelector(".meta").textContent = `could not decrypt: ${e.message}`;
        });
    } else {
      const inCart = state.cart.has(title.sku);
      const button = document.createElement("button");
      button.className = inCart ? "in-cart" : "";
      button.textContent = inCart ? "✓ in basket — remove" : `Add to basket · ${price} XTR`;
      button.addEventListener("click", () => {
        state.cart.has(title.sku) ? state.cart.delete(title.sku) : state.cart.add(title.sku);
        render();
      });
      slot.appendChild(button);
    }
    grid.appendChild(card);
  }
}

const priceOf = (sku) => priceRule(sku, state.config);

function renderOrder(record, what) {
  const amount = priceOf(record.sku);
  $("order").hidden = false;
  $("order-what").textContent = what;
  $("order-ref").textContent = record.ref;
  $("order-amount").textContent = `${amount.toLocaleString()} µXTR  ·  ${(amount / 1e6).toFixed(2)} XTR`;
  $("order-cmd").textContent = `./catflix pay ${record.ref}`;
  $("btn-cover").disabled = false;
  $("btn-cover").textContent = "no wallet? let the house pay";
  renderStatus(`Order created for ${what}. Pay it from any Ootle wallet — including one that is not the merchant's — and this page will unlock it.`, "waiting");
}

/** Mint an order for a SKU and show how to pay it. */
async function order(sku, what) {
  try {
    const record = await mintOrder(sku);
    state.cart.clear();
    render();
    renderOrder(record, what);
    renderRecovery(record);
    pollWhileWaiting();
    $("order").scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (e) {
    // Never fail silently again. The original defect was exactly this path
    // throwing into a click handler nobody was listening to.
    renderStatus(`could not create the order: ${e.message}`, "warn");
  }
}

/**
 * Put the key on screen when the browser will not keep it.
 *
 * In a published container there is no storage, so this code is the ONLY copy
 * of the purchase. Saying that plainly is the difference between a demo and a
 * way to lose somebody's money.
 */
function renderRecovery(record) {
  const panel = $("recovery");
  panel.hidden = store.available;
  if (store.available) return;
  $("recovery-code").textContent = codeFor(record);
}

/** The SKU for whatever is in the basket: one portrait is `tN`, several `mNNN`. */
function cartSku() {
  const digits = [...state.cart].map((s) => s.slice(1)).sort();
  if (digits.length === 0) return null;
  return digits.length === 1 ? `t${digits[0]}` : `m${digits.join("")}`;
}

function renderCart() {
  const bar = $("basket");
  const count = state.cart.size;
  bar.hidden = count === 0;
  if (!count) return;
  const total = (count * state.config.pricePerTitle / 1e6).toFixed(2);
  $("basket-count").textContent = count === 1 ? "1 portrait" : `${count} portraits`;
  $("basket-total").textContent = `${total} XTR`;
  $("btn-basket").textContent = `Order ${count === 1 ? "it" : "them"} · ${total} XTR`;
}

function render() {
  renderBadge();
  renderGrid();
  renderCart();
  $("keyring-count").textContent = state.keyring.length;
  $("all-price").textContent = `${(state.config.pricePerDay * 30 / 1e6).toFixed(2)} XTR`;
  $("title-price").textContent = `${(state.config.pricePerTitle / 1e6).toFixed(2)} XTR`;
  $("no-storage").hidden = store.available;
}

// ---------------------------------------------------------------------------
// the node
// ---------------------------------------------------------------------------

function connect(contractKey) {
  return new Promise((resolve, reject) => {
    // `config.node` lets the UI run from any origin against a node elsewhere,
    // which is the only way to debug it: a published web container is served
    // in a sandboxed iframe that no tool -- and no operator -- can script or
    // read the console of. Unset in the published build, where the node is
    // whatever host served the page.
    const host = state.config.node || location.host;
    // `wss:` on an https page, `ws:` on http. Hardcoding `ws:` works on a
    // local node and is silently fatal behind a domain: a browser blocks a
    // plaintext WebSocket from an https origin as mixed content, so the page
    // would load, render the whole catalogue, and never connect to anything.
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const url = new URL(`${scheme}//${host}/v1/contract/command`);
    let api;
    const handler = {
      onOpen() {
        const key = ContractKey.fromInstanceId(contractKey);
        state.key = key;
        state.api = api;
        callNode(() => api.get(new GetRequest(key, false, true, false))).catch(reject);
        // Asked for explicitly as well as via the GET flag. The two are not
        // the same request and only one of them is documented to deliver
        // update notifications.
        callNode(() => api.subscribe(new SubscribeRequest(key, new Uint8Array()))).catch(() => {});
        resolve(api);
      },
      onContractGet(response) { ingest(response.state); },
      onContractUpdateNotification(response) {
        // A subscription means the page reacts to somebody else's purchase
        // landing too -- and to its own, without polling.
        ingest(response.update?.updateData ?? response.update ?? response.state);
      },
      onContractUpdate(response) { ingest(response.state); },
      onContractPut() {},
      onContractNotFound() { renderStatus("The entitlement contract is not on this node yet.", "warn"); },
      onDelegateResponse() {},
      onErr(e) { renderStatus(`node error: ${e?.cause ?? e}`, "warn"); },
      onClose() { renderStatus("Connection to the Freenet node closed.", "warn"); },
    };
    api = new FreenetWsApi(url, handler, "");
    setTimeout(() => reject(new Error("timed out connecting to the node")), 15000);
  });
}

async function ingest(raw) {
  if (!raw) return;
  let bytes = raw;
  if (raw.buffer) bytes = new Uint8Array(raw.buffer, raw.byteOffset ?? 0, raw.byteLength ?? raw.length);
  else if (Array.isArray(raw)) bytes = new Uint8Array(raw);
  let text;
  try { text = new TextDecoder().decode(bytes); } catch { return; }
  if (!text.trim()) return;
  let register;
  try { register = JSON.parse(text); } catch { return; }
  if (!register || !Array.isArray(register.entitlements)) return;

  const before = openCount();
  try {
    if (await adoptEntitlements(register)) {
      render();
      const now = openCount();
      if (now > before) {
        $("order").hidden = true;
        renderStatus(`Payment seen on the Ootle and the envelope opened. ${now === 1 ? "One portrait is" : `${now} portraits are`} now the real thing.`, "ok");
      }
    }
  } catch (e) {
    renderStatus(`found an entitlement but could not open it: ${e.message}`, "warn");
  }
}

// ---------------------------------------------------------------------------

/**
 * One node call at a time, ever.
 *
 * The SDK is explicit that concurrent requests are delivered FIFO and get
 * mismatched to the wrong caller if they overlap. That is not a theoretical
 * hazard: the "let the house pay" button hung here — its `update` promise
 * neither resolved nor rejected — because the background poll fired a `get`
 * on top of it and took its answer. The button sat disabled forever and the
 * visitor was told nothing.
 *
 * Every call to the node goes through this chain, so the ordering the SDK
 * assumes is the ordering it actually gets.
 */
let nodeQueue = Promise.resolve();
function callNode(fn) {
  const next = nodeQueue.then(fn, fn);
  // Keep the chain alive after a rejection, but let the caller still see it.
  nodeQueue = next.then(() => {}, () => {});
  return next;
}

/**
 * Put this order's reference where the operator can see it.
 *
 * This is the ONLY way the reference can leave the page. A published Freenet
 * web container runs in a sandboxed iframe: no parent page, no extension and
 * no operator can read inside it. So "let the house pay for me" cannot be an
 * HTTP call to the house — it is a write to a second contract that the house
 * reads from the other side.
 *
 * The queue is unsigned and anyone may append to it. That is deliberate and
 * it is safe here, because an entry is a REQUEST and not access: the house
 * decides what it pays. See `contract-requests/src/lib.rs`.
 */
async function askTheHouse(reference) {
  if (!state.api) throw new Error("not connected to a node");
  // BOTH halves, and this is not optional for an UPDATE. The node gates an
  // update on already holding the contract's code blob and probes for it by
  // code hash, so `fromInstanceId` -- which leaves the code empty -- is
  // rejected outright. A GET is happy with the instance alone, which is why
  // the read path above works and only this one needed the second half.
  const key = new ContractKey(unb64(state.config.requestsInstance),
                              unb64(state.config.requestsCode));
  const bytes = new TextEncoder().encode(JSON.stringify({ v: 1, refs: [reference] }));
  const update = new UpdateData(UpdateDataType.DeltaUpdate, new DeltaUpdate(Array.from(bytes)));
  await callNode(() => state.api.update(new UpdateRequest(key, update)));
  pollWhileWaiting();
}

/**
 * Re-read the contract while an order is outstanding.
 *
 * MEASURED, not precautionary: a payment was made, the gatekeeper issued, and
 * this page went on saying "not subscribed" until it was reloaded -- at which
 * point the very same GET returned the entitlement immediately. So the read
 * path was always right and only the live notification never arrived.
 *
 * A subscription that silently does not deliver is indistinguishable from a
 * customer who has not paid yet, and the customer is the one left looking at
 * a locked page after their money is gone. So the page polls, slowly, and
 * only while it is actually waiting for something. If the notification does
 * arrive, `ingest` unlocks and this stops on its next tick.
 */
function pollWhileWaiting() {
  if (state.polling) return;
  state.polling = setInterval(async () => {
    if (!state.api || !state.key) {
      clearInterval(state.polling);
      state.polling = null;
      return;
    }
    // Serialised by construction -- one interval, one in-flight read. The SDK
    // delivers responses in FIFO order and mismatches them if reads overlap.
    if (state.reading) return;
    state.reading = true;
    try { await callNode(() => state.api.get(new GetRequest(state.key, false, false, false))); }
    catch { /* a node that refuses one read may answer the next */ }
    finally { state.reading = false; }
  }, 6000);
}

async function main() {
  state.catalog = await (await fetch("catalog.json")).json();
  state.config = await (await fetch("config.json")).json();
  state.keyring = await loadKeyring();
  $("contract-key").textContent = state.config.contract;
  $("component").textContent = state.config.component;
  render();

  $("btn-subscribe").addEventListener("click", () =>
    order("all", `all ${state.catalog.titles.length} portraits for 30 days`));

  $("btn-basket").addEventListener("click", () => {
    const sku = cartSku();
    if (!sku) return;
    const names = state.catalog.titles
      .filter((t) => state.cart.has(t.sku)).map((t) => `“${t.title}”`);
    order(sku, `${names.join(", ")} — kept forever`);
  });

  $("btn-restore").addEventListener("click", async () => {
    const text = $("restore-code").value;
    if (!text.trim()) return;
    try {
      const added = await importCode(text);
      $("restore-code").value = "";
      renderStatus(added ? "Key restored. Reading Freenet for anything it opens…"
                         : "That key was already here.", "");
      if (state.api && state.key) await callNode(() => state.api.get(new GetRequest(state.key, false, false, false)));
    } catch (e) {
      renderStatus(`could not restore that code: ${e.message}`, "warn");
    }
  });

  for (const [id, source] of [["btn-copy", () => $("order-ref").textContent],
                              ["btn-copy-code", () => $("recovery-code").textContent]]) {
    $(id).addEventListener("click", () => {
      navigator.clipboard?.writeText(source());
      const before = $(id).textContent;
      $(id).textContent = "copied";
      setTimeout(() => ($(id).textContent = before), 1400);
    });
  }
  $("btn-cover").addEventListener("click", async () => {
    const button = $("btn-cover");
    button.disabled = true;
    try {
      await Promise.race([
        askTheHouse($("order-ref").textContent),
        // 45s, not 20. MEASURED: the first write to a freshly published queue
        // contract took about fifteen seconds, because the node has to fetch
        // the contract before it can run its update. A timeout tight enough to
        // trip on that would tell a visitor the house is unreachable at the one
        // moment it is actually working.
        new Promise((_, no) => setTimeout(() => no(new Error("the node did not answer in 45s")), 45000)),
      ]);
      button.textContent = "asked — the house pays when it next sweeps";
      renderStatus("Your reference is in the request queue on Freenet. The house reads that queue and pays; this page keeps watching.", "waiting");
    } catch (e) {
      button.disabled = false;
      renderStatus(`could not reach the request queue: ${e.message}`, "warn");
    }
  });
  try {
    await connect(state.config.contract);
    renderStatus("Watching the entitlement contract on Freenet.", "");
  } catch (e) {
    renderStatus(`Could not reach the Freenet node: ${e.message}`, "warn");
  }
}

main();
