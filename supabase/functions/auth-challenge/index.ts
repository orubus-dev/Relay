// ─────────────────────────────────────────────────────────────────────────────
// Relay auth-challenge — OTP broker for partner apps (ExamForge etc.).
//
//   POST /auth/otp        { client_id, client_secret, username }
//                         → resolves the Relay account by username and emails a
//                           6-digit one-time code (Relay SMTP via GoTrue).
//                         → { challenge_id, destination_hint, expires_in }
//
//   POST /auth/otp/verify { client_id, client_secret, challenge_id, code }
//                         → checks the code with GoTrue, marks the challenge
//                           consumed.
//                         → { ok, external_id, username, display_name }
//
// Security: confidential clients only (client_id + sha256 secret, timing-safe),
// per-destination send throttling, attempt counter, single consumption.
// ─────────────────────────────────────────────────────────────────────────────

const CORS_ORIGINS = new Set([
  "https://examforage.pages.dev",
  "http://localhost:3000",
]);

function cors(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") ?? "";
  const headers: Record<string, string> = {
    "content-type": "application/json",
    vary: "Origin",
  };
  if (CORS_ORIGINS.has(origin)) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-headers"] = "content-type";
    headers["access-control-allow-methods"] = "POST, OPTIONS";
  }
  return headers;
}

function json(req: Request, body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: cors(req) });
}

function bad(req: Request, error: string, status = 400, extra?: Record<string, unknown>): Response {
  return json(req, { ok: false, error, ...(extra ?? {}) }, status);
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
  try {
    return (await req.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  SUPABASE_ANON_KEY: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return bad(req, "POST only", 405);

  const env = Deno.env.toObject() as unknown as Env;
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY } = env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return bad(req, "server_not_configured", 503);
  }

  const path = new URL(req.url).pathname.replace(/\/+$/, "").split("/").pop() ?? "";
  const body = await readJson(req);
  const clientId = String(body.client_id ?? "");
  const clientSecret = String(body.client_secret ?? "");

  // ── client authentication ──────────────────────────────────────────────────
  const appRes = await fetch(
    `${SUPABASE_URL}/rest/v1/developer_apps?client_id=eq.${encodeURIComponent(clientId)}&is_active=eq.true&select=id,name,client_secret_hash`,
    { headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` } },
  );
  const apps = appRes.ok ? (await appRes.json()) as { id: string; name: string; client_secret_hash: string | null }[] : [];
  const app = apps[0];
  if (!app || !app.client_secret_hash) return bad(req, "invalid_client", 401);
  const presentedHash = await sha256Hex(clientSecret);
  if (!timingSafeEqual(presentedHash, app.client_secret_hash)) return bad(req, "invalid_client", 401);

  if (path === "otp") return issueOtp(req, body, app, { SUPABASE_URL, SERVICE: SUPABASE_SERVICE_ROLE_KEY });
  if (path === "verify") return verifyOtp(req, body, app, { SUPABASE_URL, SERVICE: SUPABASE_SERVICE_ROLE_KEY, ANON: SUPABASE_ANON_KEY });
  return bad(req, "not_found", 404);
});

// ── POST /auth/otp ───────────────────────────────────────────────────────────
async function issueOtp(
  req: Request,
  body: Record<string, unknown>,
  app: { id: string },
  env: { SUPABASE_URL: string; SERVICE: string },
): Promise<Response> {
  const username = String(body.username ?? "").trim().toLowerCase();
  const explicitDestination = String(body.destination ?? "").trim().toLowerCase();
  if (!username && !explicitDestination) return bad(req, "username_required");

  const adminHeaders = {
    apikey: env.SERVICE,
    authorization: `Bearer ${env.SERVICE}`,
    "content-type": "application/json",
  };

  let profile: { id: string; username: string; email: string | null; display_name: string | null } | null = null;
  let destination = explicitDestination;

  if (username) {
    const res = await fetch(
      `${env.SUPABASE_URL}/rest/v1/profiles?username=ilike.${encodeURIComponent(username)}&select=id,username,email,display_name&limit=1`,
      { headers: adminHeaders },
    );
    const rows = res.ok ? (await res.json()) as typeof profile[] : [];
    profile = rows[0] ?? null;
    if (!profile) return bad(req, "unknown_username", 404);
    destination = (profile.email ?? "").toLowerCase();
    if (!destination || !destination.includes("@")) {
      return bad(req, "no_channel", 422, {
        hint: "That Relay account has no email on file — add one in Relay first.",
      });
    }
  }

  // Throttle: max 5 sends per destination per 15 minutes.
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const countRes = await fetch(
    `${env.SUPABASE_URL}/rest/v1/auth_challenges?destination=eq.${encodeURIComponent(destination)}&last_sent_at=gte.${since}&select=id`,
    { headers: adminHeaders },
  );
  const recent = countRes.ok ? (await countRes.json()) as { id: string }[] : [];
  if (recent.length >= 5) {
    return bad(req, "too_many_sends", 429, { retry_after: 900 });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const ttl = 600;
  const ins = await fetch(`${env.SUPABASE_URL}/rest/v1/auth_challenges`, {
    method: "POST",
    headers: { ...adminHeaders, prefer: "return=representation" },
    body: JSON.stringify({
      app_id: app.id,
      channel: "email",
      destination,
      code_hash: await sha256Hex(code),
      ttl_seconds: ttl,
      attempts: 0,
      expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
      last_sent_at: new Date().toISOString(),
    }),
  });
  const rows = ins.ok ? (await ins.json()) as { id: string }[] : [];
  const challenge = rows[0];
  if (!challenge) return bad(req, "challenge_failed", 500);

  // Deliver via GoTrue OTP mail (Relay SMTP). Never create accounts here.
  const otpRes = await fetch(`${env.SUPABASE_URL}/auth/v1/otp`, {
    method: "POST",
    headers: { apikey: env.SERVICE, authorization: `Bearer ${env.SERVICE}`, "content-type": "application/json" },
    body: JSON.stringify({ email: destination, create_user: false }),
  });
  if (!otpRes.ok) {
    return bad(req, "delivery_failed", 502, { challenge_id: challenge.id });
  }

  const masked = destination.replace(/^(.).*(@.*)$/, "$1•••$2");
  return json(req, {
    ok: true,
    challenge_id: challenge.id,
    destination_hint: masked,
    expires_in: ttl,
  });
}

// ── POST /auth/otp/verify ────────────────────────────────────────────────────
async function verifyOtp(
  req: Request,
  body: Record<string, unknown>,
  app: { id: string },
  env: { SUPABASE_URL: string; SERVICE: string; ANON: string },
): Promise<Response> {
  const challengeId = String(body.challenge_id ?? "");
  const code = String(body.code ?? "").trim();
  if (!challengeId || !/^\d{4,8}$/.test(code)) return bad(req, "bad_request");

  const adminHeaders = {
    apikey: env.SERVICE,
    authorization: `Bearer ${env.SERVICE}`,
    "content-type": "application/json",
  };

  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/auth_challenges?id=eq.${encodeURIComponent(challengeId)}&app_id=eq.${app.id}&select=id,destination,attempts,expires_at,consumed_at`,
    { headers: adminHeaders },
  );
  const rows = res.ok ? (await res.json()) as { id: string; destination: string; attempts: number; expires_at: string; consumed_at: string | null }[] : [];
  const ch = rows[0];
  if (!ch) return bad(req, "unknown_challenge", 404);
  if (ch.consumed_at) return bad(req, "already_used", 409);
  if (new Date(ch.expires_at).getTime() < Date.now()) return bad(req, "expired", 410);
  if (ch.attempts >= 5) return bad(req, "too_many_attempts", 429);

  // Bump attempts first (fail-closed).
  await fetch(`${env.SUPABASE_URL}/rest/v1/auth_challenges?id=eq.${ch.id}`, {
    method: "PATCH",
    headers: adminHeaders,
    body: JSON.stringify({ attempts: ch.attempts + 1 }),
  });

  // Check the code with GoTrue — it returns a session when the code is right.
  const verifyRes = await fetch(`${env.SUPABASE_URL}/auth/v1/verify`, {
    method: "POST",
    headers: { apikey: env.ANON || env.SERVICE, "content-type": "application/json" },
    body: JSON.stringify({ type: "email", email: ch.destination, token: code }),
  });
  if (!verifyRes.ok) return bad(req, "invalid_code", 401);

  // Consume our challenge.
  await fetch(`${env.SUPABASE_URL}/rest/v1/auth_challenges?id=eq.${ch.id}`, {
    method: "PATCH",
    headers: adminHeaders,
    body: JSON.stringify({ consumed_at: new Date().toISOString() }),
  });

  // Resolve the Relay profile behind the destination.
  const profRes = await fetch(
    `${env.SUPABASE_URL}/rest/v1/profiles?email=eq.${encodeURIComponent(ch.destination)}&select=id,username,display_name,email&limit=1`,
    { headers: adminHeaders },
  );
  const profiles = profRes.ok ? (await profRes.json()) as { id: string; username: string; display_name: string | null; email: string | null }[] : [];
  const profile = profiles[0];

  return json(req, {
    ok: true,
    external_id: profile?.id ?? `mail:${(await sha256Hex(ch.destination)).slice(0, 24)}`,
    username: profile?.username ?? null,
    display_name: profile?.display_name ?? profile?.username ?? null,
    email: ch.destination,
  });
}
