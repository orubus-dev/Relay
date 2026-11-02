# Relay Messaging SDK

Signal-level end-to-end encrypted messaging as two downloadable ES modules.
Drop them into any browser app, Node service, Deno or Bun project. No build
step, no native dependencies.

| File | What it is |
| --- | --- |
| `relay-sdk.mjs` | `RelayClient` — runs in your app (browser/Node/Deno/Bun). Does all the crypto. |
| `relay-server.mjs` | `RelayServer` — runs on your backend. Mints user tokens with your app secret. |

## What "Signal level" means here

The SDK implements the two protocols that make Signal Signal:

- **X3DH (Extended Triple Diffie-Hellman)** — every session starts from an
  authenticated key agreement between the two identity keys, the signed
  prekey and a one-time prekey. The prekey signature (Ed25519) is verified
  before any session is accepted, so a malicious server cannot hand you a
  fake bundle without breaking the signature.
- **Double Ratchet** — every message is sealed under a unique key derived
  from a symmetric chain; a DH ratchet runs whenever the sender's key
  changes. Compromise of your device today does not decrypt yesterday's
  messages (forward secrecy), and the session self-heals after a break-in
  (post-compromise security). Out-of-order delivery is handled with
  bounded skipped-key caching, and replays/tampering roll back cleanly.

Also in the box: X25519 key agreement, Ed25519 signatures, HKDF-SHA256,
AES-256-GCM (via the platform's WebCrypto engine), and a safety number you
can read out loud to verify a peer.

**The Relay gateway stores public prekey bundles and ciphertext envelopes
only. It never sees a private key or a plaintext word.**

## Quick start

```html
<script type="module">
  import { RelayClient } from "./relay-sdk.mjs";
</script>
```

```js
// 1) your backend mints a user token (see "Your backend" below)
const token = await fetch("/your-api/relay-token", { method: "POST" }).then((r) => r.text());

// 2) connect — generates the X3DH identity on this device and registers it
import { RelayClient } from "./relay-sdk.mjs";
const relay = new RelayClient({ appId: "rl_your_app_id", baseUrl: "https://relayid.pages.dev/v1" });
const { external_id } = await relay.connectWithToken(token);

// 3) send — the first message runs the X3DH handshake, then the ratchet takes over
await relay.send("user_43", "See you at the checkpoint");

// 4) receive
const inbox = await relay.inbox();          // decrypted view
for (const m of inbox) console.log(m.from, m.text);
await relay.markRead(inbox.map((m) => m.id));

// or handle envelopes yourself:
const { messages } = await relay.messages();
for (const m of messages) {
  console.log(await relay.decrypt(m));      // throws on tamper/replay
}
```

## Your backend

```js
import { RelayServer } from "./relay-server.mjs";
const relay = new RelayServer({ appId: "rl_your_app_id", appSecret: "rs_your_secret" });

// network mint (also validates the app secret against the gateway)
const { token } = await relay.mintToken("user_42", 3600);

// or mint offline — identical bytes, HMAC over sha256(app secret)
const { token } = relay.mintTokenLocal("user_42", 3600);
```

## API — RelayClient

| Member | Purpose |
| --- | --- |
| `new RelayClient({ appId, baseUrl, store?, opkCount?, fetch? })` | `store` is a KV adapter (defaults to localStorage, in-memory fallback); keys + sessions persist through it. |
| `connectWithToken(token)` | Authenticates and registers the prekey bundle once. |
| `send(to, text)` | Encrypts (X3DH on first message) and relays. Returns `{id, created_at}`. |
| `messages({ since?, limit? })` | Raw ciphertext envelopes. |
| `decrypt(envelope)` | Decrypts one envelope; establishes the session if it carries the handshake. |
| `inbox({ since?, limit? })` | Fetch + decrypt in one call. Undecryptable envelopes are skipped. |
| `markRead(ids)` | Read receipts. |
| `conversations()` | Partners + last activity. |
| `publicBundle()` | Your public X3DH bundle (for QR-code identity checks). |
| `safetyNumber()` | Fingerprint of your identity key — compare out of band. |
| `resetPeer(peer)` | Forget the session with a peer (after they reset their identity). |

## API — RelayServer

| Member | Purpose |
| --- | --- |
| `mintToken(externalId, ttl?)` | Mint a user token via `POST /v1/tokens`. |
| `mintTokenLocal(externalId, ttl?)` | Mint offline (no network). TTL 5 min – 7 days. |

## Rebuilding the bundles

```
npm run sdk:build      # or: node sdk/build.mjs
npx tsx sdk/test/protocol.test.ts    # protocol self-test (no network)
RELAY_APP_ID=rl_… RELAY_APP_SECRET=rs_… node sdk/test/e2e-live.mjs
```

The protocol test covers: X3DH agreement on both roles, signed-prekey
verification, 10-message ratchet flows both directions, out-of-order
delivery, replay rejection, tamper rejection, session persistence
round-trips, and the replay-rollback regression.

## Threat model (honest version)

- Encrypted against the server, passive network observers, and anyone who
  later steals ciphertext at rest.
- Key material rests in the KV store you give the SDK — in the browser that
  is localStorage, i.e. sandboxed per origin but readable by your own page
  code and any XSS on it. For hardened deployments supply a store backed by
  IndexedDB + a passphrase, or a native keystore.
- Multi-device sync is not part of v1: each device registers its own
  identity, and `resetPeer` recovers a session after a device swap.
