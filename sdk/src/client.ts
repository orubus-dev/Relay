/**
 * Relay Messaging SDK — RelayClient.
 *
 * A drop-in Signal-level messaging client. What it does:
 *   - generates an X3DH identity (identity key + Ed25519 signing key +
 *     signed prekey + one-time prekeys) on the device; private keys never
 *     leave it;
 *   - registers the public bundle with the Relay gateway;
 *   - establishes sessions lazily via X3DH on the first message to a peer;
 *   - Double-Ratchet encrypts every message (forward secrecy + break-in
 *     recovery); out-of-order delivery is handled with skipped-key caching;
 *   - the gateway only ever stores public bundles and ciphertext envelopes.
 *
 * Exported as the browser/Node/Deno/Bun entry of the SDK.
 */
import {
  b64uDecode,
  b64uEncode,
  dhPubFromPriv,
  fingerprint,
  fromUtf8,
  randomBytes,
  utf8,
  concatBytes,
} from "./crypto";
import {
  bundleFromIdentity,
  generateIdentity,
  initRatchetAsInitiator,
  initRatchetAsResponder,
  ratchetDecrypt,
  ratchetEncrypt,
  x3dhInitiate,
  x3dhRespond,
  type Envelope,
  type LocalIdentity,
  type PublicBundle,
  type SessionState,
} from "./signal";

/* ------------------------------ persistence ------------------------------ */

/** Pluggable key/value store. Default: localStorage, else in-memory. */
export interface KvStore {
  get(key: string): Promise<unknown | null>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
}

function memoryStore(): KvStore {
  const m = new Map<string, unknown>();
  return {
    async get(k) {
      return m.get(k) ?? null;
    },
    async set(k, v) {
      m.set(k, v);
    },
    async remove(k) {
      m.delete(k);
    },
  };
}

function defaultStore(): KvStore {
  try {
    if (typeof localStorage !== "undefined") {
      const ls = localStorage;
      return {
        async get(k) {
          const raw = ls.getItem(`relay-sdk:${k}`);
          return raw === null ? null : JSON.parse(raw);
        },
        async set(k, v) {
          ls.setItem(`relay-sdk:${k}`, JSON.stringify(v));
        },
        async remove(k) {
          ls.removeItem(`relay-sdk:${k}`);
        },
      };
    }
  } catch {
    /* fall through to memory */
  }
  return memoryStore();
}

/* --------------------------------- types --------------------------------- */

export type StoredIdentity = {
  ik: { priv: string; pub: string };
  sig: { priv: string; pub: string };
  spk: { priv: string; pub: string };
  spk_sig: string;
  opks: { kid: string; priv: string }[]; // X25519 private scalars, b64u
  uploaded: boolean;
};

export type DecryptedMessage = {
  id: string;
  from: string;
  text: string;
  created_at: string;
};

export type WireMessage = {
  id: string;
  sender_external_id: string;
  recipient_external_id: string;
  envelope: Envelope | Record<string, unknown>;
  created_at: string;
  delivered_at?: string | null;
  read_at?: string | null;
};

type StoredSession = {
  ad: string; // b64u of the session AD
  peerIk: string;
  ratchet: ReturnType<typeof serializeRatchet>;
  /** X3DH initiator: ephemeral pub + opk id that still need to ride the first envelope */
  pendingHandshake?: { ek: string; kid?: string };
};

export type RelayClientOptions = {
  /** developer app id, `rl_…` */
  appId: string;
  /** gateway base, e.g. https://relay-orubus.pages.dev/v1 */
  baseUrl: string;
  /** persistence for keys + sessions (defaults to localStorage/memory) */
  store?: KvStore;
  /** one-time prekeys generated on first connect (default 20) */
  opkCount?: number;
  /** optional fetch override (tests, custom agents) */
  fetch?: typeof fetch;
};

/* -------------------------------- client --------------------------------- */

export class RelayClient {
  readonly appId: string;
  readonly baseUrl: string;
  private store: KvStore;
  private opkCount: number;
  private fetchImpl: typeof fetch;
  private token: string | null = null;
  private externalId: string | null = null;
  private identity: StoredIdentity | null = null;
  private sessions = new Map<string, { ad: Uint8Array; peerIk: string; ratchet: SessionState["ratchet"]; pendingHandshake?: { ek: Uint8Array; kid?: string } }>();

  constructor(opts: RelayClientOptions) {
    if (!opts.appId?.startsWith("rl_")) throw new Error("appId must be your `rl_…` client id");
    if (!opts.baseUrl) throw new Error("baseUrl is required, e.g. https://relay-orubus.pages.dev/v1");
    this.appId = opts.appId;
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.store = opts.store ?? defaultStore();
    this.opkCount = opts.opkCount ?? 20;
    this.fetchImpl = opts.fetch ?? fetch.bind(globalThis);
  }

  /* ------------------------------ transport ------------------------------ */

  private async call<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        ...((init.headers as Record<string, string>) ?? {}),
      },
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const desc = (body.error_description as string) || (body.error as string) || `HTTP ${res.status}`;
      throw new Error(`Relay ${path}: ${desc}`);
    }
    return body as T;
  }

  /* ------------------------------- identity ------------------------------ */

  /** Load (or create once) the local X3DH identity from the store. */
  async ensureIdentity(): Promise<StoredIdentity> {
    if (this.identity) return this.identity;
    const stored = (await this.store.get(`${this.appId}:identity`)) as StoredIdentity | null;
    if (stored?.ik?.priv) {
      this.identity = stored;
    } else {
      const fresh = generateIdentity();
      this.identity = {
        ik: { priv: b64uEncode(fresh.ik.priv), pub: b64uEncode(fresh.ik.pub) },
        sig: { priv: b64uEncode(fresh.sig.priv), pub: b64uEncode(fresh.sig.pub) },
        spk: { priv: b64uEncode(fresh.spk.priv), pub: b64uEncode(fresh.spk.pub) },
        spk_sig: b64uEncode(fresh.spk_sig),
        opks: Array.from({ length: this.opkCount }, () => ({
          kid: b64uEncode(randomBytes(8)),
          priv: b64uEncode(randomBytes(32)),
        })),
        uploaded: false,
      };
      await this.store.set(`${this.appId}:identity`, this.identity);
    }
    return this.identity;
  }

  private identityFromStored(stored: StoredIdentity): LocalIdentity {
    const dec = (s: string) => b64uDecode(s);
    return {
      ik: { priv: dec(stored.ik.priv), pub: dec(stored.ik.pub) },
      sig: { priv: dec(stored.sig.priv), pub: dec(stored.sig.pub) },
      spk: { priv: dec(stored.spk.priv), pub: dec(stored.spk.pub) },
      spk_sig: dec(stored.spk_sig),
    };
  }

  /** Public bundle this device advertises (what a peer needs to open a session). */
  async publicBundle(): Promise<PublicBundle> {
    const id = await this.ensureIdentity();
    return { ik: id.ik.pub, spk: id.spk.pub, spk_sig: id.spk_sig, sig: id.sig.pub };
  }

  /** Human-readable safety number for this identity key (compare out of band). */
  async safetyNumber(): Promise<string> {
    const id = await this.ensureIdentity();
    return fingerprint(b64uDecode(id.ik.pub));
  }

  /* -------------------------------- session ------------------------------- */

  /**
   * Authenticate with a user token minted by your backend
   * (`POST {baseUrl}/tokens` with the app secret) or by Relay auth
   * (`POST /auth/otp/verify`). Registers the prekey bundle on first use.
   */
  async connectWithToken(token: string, opts: { opkCount?: number } = {}): Promise<{ external_id: string }> {
    this.token = token;
    const payloadPart = token.split(".")[0] ?? "";
    let ext = "";
    try {
      ext = String(JSON.parse(atob(payloadPart.replace(/-/g, "+").replace(/_/g, "/"))).ext ?? "");
    } catch {
      throw new Error("That is not a Relay user token.");
    }
    if (!ext) throw new Error("Relay user token has no external id.");
    this.externalId = ext;

    const stored = await this.ensureIdentity();
    if (!stored.uploaded) {
      const want = opts.opkCount ?? this.opkCount;
      while (stored.opks.length < want) {
        stored.opks.push({ kid: b64uEncode(randomBytes(8)), priv: b64uEncode(randomBytes(32)) });
      }
      const upload = {
        bundle: {
          ...bundleFromIdentity(this.identityFromStored(stored), stored.opks.map((o) => ({
            kid: o.kid,
            key: b64uEncode(dhPubFromPriv(b64uDecode(o.priv))), // publish the PUBLIC point
          }))),
          sig: stored.sig.pub, // Ed25519 verify key for the prekey signature
        },
        meta: { sdk: "relay-messaging-sdk", v: 2 },
      };
      await this.call("/identities", { method: "POST", body: JSON.stringify(upload) });
      stored.uploaded = true;
      await this.store.set(`${this.appId}:identity`, stored);
    }
    return { external_id: ext };
  }

  private sessionKey(peer: string): string {
    return `${this.appId}:sessions:${this.externalId}:${peer}`;
  }

  private async loadSession(peer: string) {
    const hit = this.sessions.get(peer);
    if (hit) return hit;
    const raw = (await this.store.get(this.sessionKey(peer))) as StoredSession | null;
    if (!raw) return null;
    const sess = {
      ad: b64uDecode(raw.ad),
      peerIk: raw.peerIk,
      ratchet: hydrateRatchet(raw.ratchet),
    };
    this.sessions.set(peer, sess);
    return sess;
  }

  private async saveSession(peer: string) {
    const sess = this.sessions.get(peer);
    if (!sess) return;
    const out: StoredSession = {
      ad: b64uEncode(sess.ad),
      peerIk: sess.peerIk,
      ratchet: serializeRatchet(sess.ratchet),
      pendingHandshake: sess.pendingHandshake
        ? { ek: b64uEncode(sess.pendingHandshake.ek), kid: sess.pendingHandshake.kid }
        : undefined,
    };
    await this.store.set(this.sessionKey(peer), out);
  }

  private async dropSession(peer: string): Promise<void> {
    this.sessions.delete(peer);
    await this.store.remove(this.sessionKey(peer));
  }

  /** Forget the session with a peer (e.g. after they reset their identity). */
  async resetPeer(peer: string): Promise<void> {
    await this.dropSession(peer.trim());
  }

  /* --------------------------------- send --------------------------------- */

  /**
   * Encrypt + send. On the first message to a peer this performs the full
   * X3DH handshake against their bundle; afterwards the Double Ratchet
   * carries every message.
   */
  async send(to: string, text: string): Promise<{ id: string; created_at: string }> {
    if (!this.externalId) throw new Error("connectWithToken() first.");
    const peer = to.trim();
    if (!peer || peer === this.externalId) throw new Error("invalid recipient");

    let sess = await this.loadSession(peer);
    if (!sess) {
      // X3DH: fetch the peer bundle (consumes one of their one-time prekeys)
      const res = await this.call<{
        bundle: PublicBundle;
        one_time_prekey: { kid: string; key: string } | null;
      }>(`/identities/${encodeURIComponent(peer)}`);
      const me = await this.ensureIdentity();
      const identity = this.identityFromStored(me);
      const { secret, ek, usedOpk } = x3dhInitiate(identity, {
        bundle: res.bundle,
        one_time_prekey: res.one_time_prekey,
      });
      // session AD binds both identity keys (order-independent)
      const ad = sortConcat(identity.ik.pub, b64uDecode(res.bundle.ik));
      sess = {
        ...initRatchetAsInitiator(secret, b64uDecode(res.bundle.spk), ad),
        peerIk: res.bundle.ik,
        pendingHandshake: { ek: ek.pub, kid: usedOpk?.kid },
      };
      this.sessions.set(peer, sess);
    }

    const envelope = await ratchetEncrypt(sess.ratchet, sess.ad, utf8(text));
    if (sess.pendingHandshake) {
      // first envelope carries the X3DH handshake (initiator IK + ephemeral + opk id)
      envelope.x_ik = (await this.publicBundle()).ik;
      envelope.ek = b64uEncode(sess.pendingHandshake.ek);
      if (sess.pendingHandshake.kid) envelope.kid = sess.pendingHandshake.kid;
      sess.pendingHandshake = undefined;
    }
    await this.saveSession(peer);

    return this.call("/messages", {
      method: "POST",
      body: JSON.stringify({ to: peer, envelope }),
    });
  }

  /* -------------------------------- receive ------------------------------- */

  /**
   * Fetch ciphertext envelopes. Use decrypt() on each — or inbox() for the
   * decrypted view directly.
   */
  async messages(opts: { since?: string; limit?: number } = {}): Promise<{ messages: WireMessage[] }> {
    if (!this.externalId) throw new Error("connectWithToken() first.");
    const q = new URLSearchParams();
    if (opts.since) q.set("since", opts.since);
    if (opts.limit) q.set("limit", String(opts.limit));
    const qs = q.toString();
    return this.call(`/messages${qs ? `?${qs}` : ""}`);
  }

  /**
   * Decrypt an inbound envelope. Establishes the session via X3DH when this
   * is the peer's first message (responder role) and advances the ratchet.
   */
  async decrypt(message: { sender_external_id: string; envelope: Envelope }): Promise<string> {
    if (!this.externalId) throw new Error("connectWithToken() first.");
    const peer = message.sender_external_id;
    const env = message.envelope;
    if (!env || env.v !== 2 || !env.header) throw new Error("unsupported envelope");

    let sess = await this.loadSession(peer);
    if (!sess) {
      if (!env.ek || !env.x_ik) {
        throw new Error("no session with that peer and the envelope carries no handshake");
      }
      // X3DH responder: recompute the shared secret from our private prekeys
      const stored = await this.ensureIdentity();
      const identity = this.identityFromStored(stored);
      const opkMap = new Map<string, Uint8Array>(stored.opks.map((o) => [o.kid, b64uDecode(o.priv)]));
      const { secret, consumedOpkKid } = x3dhRespond(
        identity,
        opkMap,
        env.x_ik,
        env.ek,
        env.kid,
      );
      // AD must match the initiator: sort-concat of both identity keys
      const ad = sortConcat(b64uDecode(env.x_ik), identity.ik.pub);
      sess = {
        ...initRatchetAsResponder(secret, identity.spk, ad),
        peerIk: env.x_ik,
      };
      this.sessions.set(peer, sess);
      if (consumedOpkKid) {
        // the OPK did its job — forget the private half
        stored.opks = stored.opks.filter((o) => o.kid !== consumedOpkKid);
        await this.store.set(`${this.appId}:identity`, stored);
        // keep at least a few OPKs in stock
        if (stored.opks.length < 5) await this.topUpOpks(stored, 15);
      }
    }

    const pt = await ratchetDecrypt(sess.ratchet, sess.ad, env);
    await this.saveSession(peer);
    return fromUtf8(pt);
  }

  private async topUpOpks(stored: StoredIdentity, count: number): Promise<void> {
    const fresh = Array.from({ length: count }, () => ({
      kid: b64uEncode(randomBytes(8)),
      priv: b64uEncode(randomBytes(32)),
    }));
    stored.opks.push(...fresh);
    await this.store.set(`${this.appId}:identity`, stored);
    await this.call("/identities/opks", {
      method: "POST",
      body: JSON.stringify({
        opks: fresh.map((o) => ({ kid: o.kid, key: b64uEncode(dhPubFromPriv(b64uDecode(o.priv))) })),
      }),
    });
  }

  /** Convenience: fetch + decrypt everything waiting for us. */
  async inbox(opts: { since?: string; limit?: number } = {}): Promise<DecryptedMessage[]> {
    const { messages } = await this.messages(opts);
    const out: DecryptedMessage[] = [];
    for (const m of messages) {
      try {
        const text = await this.decrypt({
          sender_external_id: m.sender_external_id,
          envelope: m.envelope as Envelope,
        });
        out.push({ id: m.id, from: m.sender_external_id, text, created_at: m.created_at });
      } catch (err) {
        // envelope we cannot open (other device, rotated identity) — drop through
        void err;
      }
    }
    return out;
  }

  async markRead(ids: string[]): Promise<void> {
    if (!ids.length) return;
    await this.call("/messages/read", { method: "POST", body: JSON.stringify({ ids }) });
  }

  async conversations(): Promise<{ conversations: { partner: string; last_at: string }[] }> {
    return this.call("/conversations");
  }

  get me(): string | null {
    return this.externalId;
  }
}

/* ------------------------------- internals ------------------------------- */

function serializeRatchet(r: SessionState["ratchet"]): Record<string, unknown> {
  return {
    rk: b64uEncode(r.rk),
    cks: r.cks ? b64uEncode(r.cks) : null,
    ckr: r.ckr ? b64uEncode(r.ckr) : null,
    dhs_priv: b64uEncode(r.dhs_priv),
    dhs_pub: b64uEncode(r.dhs_pub),
    dhr: r.dhr ? b64uEncode(r.dhr) : null,
    ns: r.ns,
    nr: r.nr,
    pn: r.pn,
    skipped: r.skipped.map((s) => ({ dh: s.dh, n: s.n, mk: b64uEncode(s.mk) })),
  };
}

function hydrateRatchet(r: Record<string, unknown>): SessionState["ratchet"] {
  return {
    rk: b64uDecode(r.rk as string),
    cks: r.cks ? b64uDecode(r.cks as string) : null,
    ckr: r.ckr ? b64uDecode(r.ckr as string) : null,
    dhs_priv: b64uDecode(r.dhs_priv as string),
    dhs_pub: b64uDecode(r.dhs_pub as string),
    dhr: r.dhr ? b64uDecode(r.dhr as string) : null,
    ns: r.ns as number,
    nr: r.nr as number,
    pn: r.pn as number,
    skipped: (r.skipped as { dh: string; n: number; mk: string }[]).map((s) => ({
      dh: s.dh,
      n: s.n,
      mk: b64uDecode(s.mk),
    })),
  };
}

/** AD = both identity keys concatenated in sorted order (order-independent). */
function sortConcat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const aS = b64uEncode(a);
  const bS = b64uEncode(b);
  return aS <= bS ? concatBytes(a, b) : concatBytes(b, a);
}
