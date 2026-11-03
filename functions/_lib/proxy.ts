/**
 * Hardened same-origin Supabase proxy for Cloudflare Pages Functions.
 *
 * Restores the "hidden plumber" lane the apps had on Vercel: the browser
 * talks to its own origin (/auth/v1/*, /rest/v1/*, /storage/v1/*,
 * /functions/v1/*) and this function streams the call to the fixed project
 * host. Without it, auth calls hit the SPA shell (405/HTML) — the root cause
 * of the signup "Unexpected end of JSON input" and the OAuth
 * "page-refresh-then-nothing" symptom on Cloudflare Pages.
 *
 * Security posture (this file is the whole threat model):
 *  - FIXED upstream host compiled in below. The path comes from the route
 *    mount only; it can never change the destination host (no SSRF).
 *  - No open proxy: only this project's Supabase host is reachable.
 *  - Path hygiene: traversal ("..", encoded dots), NULs, oversized paths and
 *    empty catch-alls are rejected before any upstream byte is sent.
 *  - Header allowlist: only the headers Supabase actually consumes are
 *    forwarded. Cookies are NEVER forwarded upstream (auth is stateless JWT
 *    in headers; GoTrue binds OAuth flows server-side, not via cookies) and
 *    upstream Set-Cookie is stripped on the way back (no cross-domain cookie
 *    injection into the app origin).
 *  - Body caps per route class, enforced from Content-Length before a single
 *    body byte is buffered; bodies are streamed, not buffered.
 *  - Per-IP token-bucket rate limits per route class (best-effort, per
 *    isolate — Cloudflare's edge protections stack on top, and GoTrue enforces
 *    its own per-endpoint limits upstream).
 *  - Upstream redirects are passed through untouched (redirect: "manual") so
 *    the browser — not this function — follows OAuth hops.
 */

export const UPSTREAM_HOST = "gobwknacvpgysmgpvzqt.supabase.co";

/** Route class knobs: (body cap bytes, upstream timeout ms, rate limit/min). */
export type RouteClass = "auth" | "rest" | "storage" | "functions" | "realtime";

const CLASS_LIMITS: Record<RouteClass, { body: number; timeout: number; rpm: number }> = {
  auth: { body: 1_000_000, timeout: 25_000, rpm: 60 },
  rest: { body: 2_000_000, timeout: 25_000, rpm: 240 },
  storage: { body: 64_000_000, timeout: 55_000, rpm: 120 },
  functions: { body: 2_000_000, timeout: 30_000, rpm: 60 },
  realtime: { body: 0, timeout: 30_000, rpm: 120 },
};

/** Headers we forward upstream — everything else is dropped. */
const REQ_HEADER_ALLOW = new Set([
  "authorization",
  "apikey",
  "content-type",
  "accept",
  "accept-language",
  "user-agent",
  "x-client-info",
  "x-supabase-api-version",
  "x-supabase-transition",
  "prefer",
  "range",
  "if-match",
  "if-none-match",
  "if-modified-since",
  "if-range",
  "cache-control",
  "content-length",
]);

/** Headers never copied back to the browser. */
const RES_HEADER_DENY = new Set([
  "set-cookie",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "strict-transport-security",
]);

// --- best-effort per-isolate rate limiting --------------------------------
const buckets = new Map<string, { n: number; reset: number }>();

function rateLimit(key: string, limitPerMin: number): boolean {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || now >= b.reset) {
    if (buckets.size > 10_000) {
      for (const [k, v] of buckets) if (now >= v.reset) buckets.delete(k);
    }
    buckets.set(key, { n: 1, reset: now + 60_000 });
    return true;
  }
  b.n += 1;
  return b.n <= limitPerMin;
}

function clientIp(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    "unknown"
  );
}

function isUnsafePath(pathname: string): boolean {
  if (!pathname || pathname.length > 1_024) return true;
  if (pathname.includes("\0")) return true;
  const lower = decodeURIComponent(pathname).toLowerCase();
  if (lower.includes("..")) return true;
  // collapse-check: no empty segments beyond the leading slash
  return /[^/]\/\/[^/]/.test(pathname);
}

export type ProxyOptions = {
  routeClass: RouteClass;
  /** Rewrite the upstream path (e.g. /v1/x -> /functions/v1/x). */
  rewrite?: (pathname: string) => string;
};

export async function proxySupabase(request: Request, opts: ProxyOptions): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const limits = CLASS_LIMITS[opts.routeClass];

  if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(method)) {
    return json({ error: "method_not_allowed" }, 405);
  }
  if (isUnsafePath(url.pathname)) {
    return json({ error: "bad_path" }, 400);
  }
  if (!rateLimit(`${opts.routeClass}:${clientIp(request)}`, limits.rpm)) {
    return json({ error: "rate_limited", hint: "slow down" }, 429, { "retry-after": "30" });
  }

  const bodyCap = Number(request.headers.get("content-length") ?? "0");
  if (bodyCap > limits.body) {
    return json({ error: "payload_too_large", max_bytes: limits.body }, 413);
  }

  const upstreamPath = opts.rewrite ? opts.rewrite(url.pathname) : url.pathname;
  const target = `https://${UPSTREAM_HOST}${upstreamPath}${url.search}`;

  const headers = new Headers();
  for (const [k, v] of request.headers.entries()) {
    if (REQ_HEADER_ALLOW.has(k.toLowerCase())) headers.set(k, v);
  }
  headers.set("user-agent", "orubus-pages-proxy (+same-origin)");

  const hasBody = !["GET", "HEAD", "OPTIONS"].includes(method);
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method,
      headers,
      body: hasBody ? (request.body as unknown as BodyInit) : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(limits.timeout),
    });
  } catch (e) {
    const msg = e instanceof Error && /abort|timeout/i.test(e.name + e.message) ? "upstream_timeout" : "upstream_unreachable";
    return json({ error: msg }, 502);
  }

  const out = new Headers();
  for (const [k, v] of upstream.headers.entries()) {
    if (!RES_HEADER_DENY.has(k.toLowerCase())) out.set(k, v);
  }
  out.set("x-content-type-options", "nosniff");
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: out,
  });
}

function json(obj: unknown, status: number, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "x-content-type-options": "nosniff", ...(extra ?? {}) },
  });
}
