/**
 * Relay Messaging SDK — RelayServer (backend helper).
 *
 * Your backend holds the app secret (`rs_…`). With it you mint short-lived
 * user tokens that authenticate SDK calls:
 *
 *   const relay = new RelayServer({ appId, appSecret });
 *   const token = await relay.mintToken("user_42");            // calls /tokens
 *   const local = await relay.mintTokenLocal("user_42", 3600); // offline, HMAC
 *
 * Tokens carry {cid, ext, exp} and are HMAC'd with sha256(appSecret) — the
 * same value the gateway stores as client_secret_hash, so nobody without the
 * app secret can mint identities.
 */
import { sha256 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import { b64uEncode } from "./crypto";

const te = new TextEncoder();

function sha256Hex(text: string): string {
  return [...sha256(te.encode(text))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
}

/** HMAC-SHA256 over the ASCII body — mirrors _shared/relay.ts signUserToken. */
function hmacBody(key: Uint8Array, body: string): Uint8Array {
  return hmac(sha256, key, te.encode(body));
}

export type RelayServerOptions = {
  appId: string;
  appSecret: string;
  baseUrl?: string;
  fetch?: typeof fetch;
};

export class RelayServer {
  readonly appId: string;
  readonly appSecret: string;
  readonly baseUrl: string;
  private fetchImpl: typeof fetch;

  constructor(opts: RelayServerOptions) {
    if (!opts.appId?.startsWith("rl_")) throw new Error("appId must be your `rl_…` client id");
    if (!opts.appSecret?.startsWith("rs_")) throw new Error("appSecret must be your `rs_…` client secret");
    this.appId = opts.appId;
    this.appSecret = opts.appSecret;
    this.baseUrl = (opts.baseUrl ?? "https://relay-orubus.pages.dev/v1").replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? fetch.bind(globalThis);
  }

  /** Mint a user token through the gateway (needs network). */
  async mintToken(
    externalId: string,
    ttlSeconds = 86400,
  ): Promise<{ token: string; external_id: string; expires_in: number }> {
    const res = await this.fetchImpl(`${this.baseUrl}/tokens`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.appSecret}`,
      },
      body: JSON.stringify({ external_id: externalId, ttl_seconds: ttlSeconds }),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const desc = (body.error_description as string) || (body.error as string) || `HTTP ${res.status}`;
      throw new Error(`Relay /tokens: ${desc}`);
    }
    return body as { token: string; external_id: string; expires_in: number };
  }

  /**
   * Mint the same token offline — identical bytes to what the gateway
   * produces, because the gateway verifies HMAC(key = sha256hex(app secret)).
   */
  mintTokenLocal(externalId: string, ttlSeconds = 86400): { token: string; expires_in: number } {
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.max(300, Math.min(ttlSeconds, 7 * 86400));
    const exp = now + ttl;
    const payload = { cid: this.appId, ext: externalId, exp };
    const body = b64uEncode(te.encode(JSON.stringify(payload)));
    const key = hexToBytes(sha256Hex(this.appSecret));
    const sig = hmacBody(key, body);
    return { token: `${body}.${b64uEncode(sig)}`, expires_in: ttl };
  }
}
