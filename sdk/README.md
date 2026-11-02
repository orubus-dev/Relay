# Relay Messaging SDK

Encrypted messaging for your app, your VPS or any backend provider.
**You add the SDK. Relay handles identity, key exchange, encryption, delivery and storage.**

Your users keep their own ids (`user_42`, whatever your database says). Your backend never
touches cryptography, never sees a private key and never stores plaintext. Relay's backend
is the hidden plumber: it routes ciphertext envelopes and nothing else.

```
your app                      relay (hidden plumber)
┌──────────────┐   envelopes  ┌─────────────────────┐
│ RelayClient  │ ───────────▶ │ relay-orubus.pages.dev  │ ─▶ recipient's devices
│ (WebCrypto)  │ ◀─────────── │ /v1/*               │
└──────────────┘   envelopes  └─────────────────────┘
        ▲ user token minted by YOUR backend with RelayServer
```

## Install

```bash
npm i @relay/messaging-sdk
```

Works in the browser, Node 18+, Bun, Deno and edge runtimes. Zero dependencies.
Encryption is ECDH (P-256) + HKDF-SHA256 + AES-256-GCM through WebCrypto, with a fresh
ephemeral key pair per message.

## What you need first

1. **A business profile** on Relay: Profile → Developer → open developer page.
2. **An app** with the **Messaging SDK** product → copy the `client_id` (`rl_…`) and the
   `client_secret` (`rs_…`, shown once).
3. Scopes: check `messages:send` and `messages:read` on the app.

## 1. Mint user tokens on YOUR backend

```ts
// your server (Express example)
import { RelayServer } from '@relay/messaging-sdk/server';

const relay = new RelayServer(process.env.RELAY_APP_SECRET!, 'rl_your_app_id');

app.post('/relay-token', requireLogin, (req, res) => {
  // externalId = your own user id, any string up to 128 chars
  res.type('text').send(relay.userToken(req.session.userId));
});
```

The token is a short-lived HMAC your gateway can verify against the hashed secret.
Your app secret never reaches the browser.

## 2. Connect from the browser

```ts
import { RelayClient } from '@relay/messaging-sdk';

const relay = new RelayClient({ appId: 'rl_your_app_id' });

const res = await fetch('/relay-token');          // your backend
await relay.connectWithToken(await res.text());   // registers the device key bundle
```

First connect generates the device identity key pair. The private key stays in the
browser (export with `relay.exportIdentity()` to migrate a user between devices).

## 3. Send and receive

```ts
await relay.send('user_43', 'See you at the checkpoint');

const inbox = await relay.messages();             // ciphertext envelopes
for (const m of inbox.messages) {
  console.log(m.from, await relay.decrypt(m));    // decrypted locally
}
await relay.markRead(inbox.messages.map((m) => m.id));

const convos = await relay.conversations();       // partners + last activity
```

## 4. Optional: your own tables

Mirror whatever your product needs on your own database. Relay keeps identity bundles
and ciphertext envelopes; you keep product data:

```sql
create table relay_receipts (
  relay_message_id     uuid primary key,
  sender_external_id   text not null,
  recipient_external_id text not null,
  created_at           timestamptz not null default now()
);
```

Wire your own webhooks by posting to your backend from your frontend message handler,
or poll `relay.messages(since)` on an interval.

## 5. Relay sign-in (Integrate auth apps)

If your app also uses Relay as an identity provider (the "Integrate auth" product), the
whole OAuth surface lives on our domain:

| endpoint  | url                                          |
| --------- | -------------------------------------------- |
| authorize | `https://relay-orubus.pages.dev/consent`         |
| token     | `https://relay-orubus.pages.dev/v1/oauth/token`  |
| userinfo  | `https://relay-orubus.pages.dev/v1/oauth/userinfo` |
| redirect  | `https://relay-orubus.pages.dev/v1/redirect`     |

OAuth 2.0 with PKCE (S256), exactly like "Continue with Google".

## API reference

### `new RelayClient({ appId, baseUrl?, keyPrefix? })`
`baseUrl` defaults to `https://relay-orubus.pages.dev/v1`.

### client methods
- `connectWithToken(token)` → `{ externalId }` — register/refresh the device key bundle
- `send(to, text)` → `{ id, created_at }` — seals and posts an envelope
- `messages(since?, limit?)` → ciphertext inbox (marks delivered)
- `decrypt(message)` → plaintext string
- `markRead(ids)`
- `conversations()` → partners with last activity
- `peerBundle(externalId)` → a peer's public key bundle
- `exportIdentity()` / `importIdentity(raw)` — move a user between devices

### `new RelayServer(appSecret, appId?)` (server subpath)
- `userToken(externalId, ttlSeconds?)` → HMAC token for the browser SDK
- `setAppId(appId)`

## Threat model, straight up

- Private keys live on the user's device. Relay stores public bundles only.
- Every message is sealed with a fresh ephemeral key: compromise of one message never
  unlocks another.
- Relay can see who talks to whom and when (metadata) but never the content.
- Lost device without an identity export = lost history. Export early.
