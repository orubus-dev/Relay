// ─────────────────────────────────────────────────────────────────────────────
// Relay auth-challenge — OTP broker for partner apps (ExamForge etc.).
//
//   POST /auth/otp        { client_id, client_secret, username }
//                         → resolves the Relay account by username and drops a
//                           one-time code DIRECTLY into the user's Relay chats
//                           as a DM from the app's official business account
//                           (no email involved).
//                         → { challenge_id, destination_hint, expires_in }
//
//   POST /auth/otp/verify { client_id, client_secret, challenge_id, code }
//                         → checks the code against the stored hash (timing-
//                           safe), marks the challenge consumed.
//                         → { ok, external_id, username, display_name }
//
// Security: confidential clients only (client_id + sha256 secret, timing-safe),
// per-destination + per-app send throttling, attempt counter, single use,
// TTL-bounded codes, business profile is a banned auth user (cannot ever hold
// a session), DM inserted with the service role only inside this function.
// ─────────────────────────────────────────────────────────────────────────────

const BIZ_FALLBACK_EMAIL = "official@relay-business.internal";
const CODE_TTL_SECONDS = 600;
const MAX_SENDS_PER_DESTINATION = 5; // per 15 min
const MAX_SENDS_PER_APP = 120; // per 15 min, global spam ceiling
const THROTTLE_WINDOW_MS = 15 * 60 * 1000;

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

/** Unbiased 6-digit numeric code. */
function sixDigitCode(): string {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0xffffffff / 10) * 10;
  let v = 0;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return String(v % 1000000).padStart(6, "0");
}

interface Env {
  SUPABASE_URL: string;
  SUPABASE_SERVICE_ROLE_KEY: string;
  SUPABASE_ANON_KEY: string;
}

interface RestClient {
  get<T>(path: string): Promise<{ ok: boolean; rows: T[] }>;
  post<T>(path: string, body: unknown, preferRepresentation?: boolean): Promise<{ ok: boolean; rows: T[] }>;
  patch(path: string, body: unknown): Promise<{ ok: boolean }>;
}

function rest(env: { SUPABASE_URL: string; SERVICE: string }): RestClient {
  const base = `${env.SUPABASE_URL}/rest/v1`;
  const h = { apikey: env.SERVICE, authorization: `Bearer ${env.SERVICE}` };
  return {
    async get<T>(path: string) {
      const r = await fetch(`${base}/${path}`, { headers: h, cache: "no-store" });
      const rows = r.ok ? (await r.json()) as T[] : [];
      return { ok: r.ok, rows };
    },
    async post<T>(path: string, body: unknown, preferRepresentation = false) {
      const r = await fetch(`${base}/${path}`, {
        method: "POST",
        headers: { ...h, "content-type": "application/json", prefer: preferRepresentation ? "return=representation" : "return=minimal" },
        body: JSON.stringify(body),
      });
      const rows = preferRepresentation && r.ok ? (await r.json()) as T[] : [];
      return { ok: r.ok, rows };
    },
    async patch(path: string, body: unknown) {
      const r = await fetch(`${base}/${path}`, {
        method: "PATCH",
        headers: { ...h, "content-type": "application/json", prefer: "return=minimal" },
        body: JSON.stringify(body),
      });
      return { ok: r.ok };
    },
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return bad(req, "POST only", 405);

  const env = Deno.env.toObject() as unknown as Env;
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return bad(req, "server_not_configured", 503);
  }
  const db = rest({ SUPABASE_URL, SERVICE: SUPABASE_SERVICE_ROLE_KEY });

  const path = new URL(req.url).pathname.replace(/\/+$/, "").split("/").pop() ?? "";
  const body = await readJson(req);
  const clientId = String(body.client_id ?? "");
  const clientSecret = String(body.client_secret ?? "");

  // ── client authentication ──────────────────────────────────────────────────
  const appRes = await db.get<{ id: string; name: string; business_id: string | null; client_secret_hash: string | null }>(
    `developer_apps?client_id=eq.${encodeURIComponent(clientId)}&is_active=eq.true&select=id,name,business_id,client_secret_hash`,
  );
  const app = appRes.rows[0];
  if (!app || !app.client_secret_hash) return bad(req, "invalid_client", 401);
  const presentedHash = await sha256Hex(clientSecret);
  if (!timingSafeEqual(presentedHash, app.client_secret_hash)) return bad(req, "invalid_client", 401);

  if (path === "otp") return issueOtp(req, body, app, { SUPABASE_URL, SERVICE: SUPABASE_SERVICE_ROLE_KEY }, db);
  if (path === "verify") return verifyOtp(req, body, app, { SUPABASE_URL, SERVICE: SUPABASE_SERVICE_ROLE_KEY }, db);
  return bad(req, "not_found", 404);
});

// ── business sender identity ─────────────────────────────────────────────────
// The DM comes FROM the app's official Relay account. It is a normal profile
// backed by a permanently banned auth user (nobody can ever log into it).

interface Sender {
  profileId: string;
  displayName: string;
}

async function ensureBusinessSender(
  app: { id: string; business_id: string | null },
  env: { SUPABASE_URL: string; SERVICE: string },
  db: RestClient,
): Promise<Sender | null> {
  // 1. Which business owns this app?
  let bizUsername = "examforge";
  let bizName = "ExamForge";
  if (app.business_id) {
    const biz = await db.get<{ name: string; username: string }>(
      `developer_businesses?id=eq.${encodeURIComponent(app.business_id)}&select=name,username&limit=1`,
    );
    if (biz.rows[0]) {
      bizUsername = String(biz.rows[0].username || bizUsername).toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 30);
      bizName = biz.rows[0].name || bizName;
      if (bizUsername.length < 3) bizUsername = "examforge";
    }
  }

  // 2. Does a profile with that username exist?
  const found = await db.get<{ id: string; display_name: string }>(
    `profiles?username=eq.${encodeURIComponent(bizUsername)}&select=id,display_name&limit=1`,
  );
  if (found.rows[0]) {
    return { profileId: found.rows[0].id, displayName: found.rows[0].display_name || bizName };
  }

  // 3. Create the backing auth user (banned forever — session-proof).
  const adminRes = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
    method: "POST",
    headers: { apikey: env.SERVICE, authorization: `Bearer ${env.SERVICE}`, "content-type": "application/json" },
    body: JSON.stringify({
      email: `${bizUsername}@${BIZ_FALLBACK_EMAIL.split("@")[1]}`,
      email_confirm: true,
      ban_duration: "876000h", // 100 years
      user_metadata: { username: bizUsername, full_name: bizName },
    }),
  });
  if (!adminRes.ok) return null;
  const created = (await adminRes.json()) as { id?: string };
  const userId = created.id;
  if (!userId) return null;

  // 4. Shape the public profile.
  await db.patch(
    `profiles?id=eq.${encodeURIComponent(userId)}`,
    {
      display_name: bizName,
      full_name: bizName,
      email: null,
      avatar_url: null,
      bio: `Official ${bizName} business account. Sign-in codes and notices from ${bizName} arrive here.`,
      status_message: "Verified business",
      is_verified: true,
      account_status: "active",
      onboarding_completed: true,
      updated_at: new Date().toISOString(),
    },
  );
  return { profileId: userId, displayName: bizName };
}

// ── direct conversation between the business sender and the user ────────────
async function findOrCreateDirectChat(
  db: RestClient,
  aId: string,
  bId: string,
  sender: Sender,
): Promise<string | null> {
  const mine = await db.get<{ conversation_id: string }>(
    `conversation_members?profile_id=eq.${encodeURIComponent(aId)}&status=eq.active&select=conversation_id`,
  );
  const theirs = await db.get<{ conversation_id: string }>(
    `conversation_members?profile_id=eq.${encodeURIComponent(bId)}&status=eq.active&select=conversation_id`,
  );
  if (!mine.ok || !theirs.ok) return null;
  const theirSet = new Set(theirs.rows.map((r) => r.conversation_id));
  const shared = mine.rows.map((r) => r.conversation_id).filter((id) => theirSet.has(id));
  if (shared.length > 0) {
    const conv = await db.get<{ id: string }>(
      `conversations?id=in.(${shared.join(",")})&conversation_type=eq.direct&select=id&limit=1`,
    );
    if (conv.rows[0]) return conv.rows[0].id;
  }

  // Create the direct conversation + membership rows + a one-time welcome note.
  const created = await db.post<{ id: string }>(
    "conversations",
    { conversation_type: "direct", created_by: aId, is_public: false, max_members: 2 },
    true,
  );
  const convId = created.rows[0]?.id;
  if (!convId) return null;

  await db.post("conversation_members", [
    { conversation_id: convId, profile_id: aId, role: "member", status: "active", request_status: "accepted", unread_count: 0 },
    { conversation_id: convId, profile_id: bId, role: "member", status: "active", request_status: "accepted", unread_count: 0 },
  ]);
  await db.post("messages", {
    conversation_id: convId,
    sender_id: aId,
    message_type: "text",
    content: `Welcome to ${sender.displayName} on Relay. This is the official ${sender.displayName} account — sign-in codes and notices will arrive here as chat messages.`,
    send_status: "sent",
  });
  return convId;
}

// ── POST /auth/otp ───────────────────────────────────────────────────────────
async function issueOtp(
  req: Request,
  body: Record<string, unknown>,
  app: { id: string; business_id: string | null },
  env: { SUPABASE_URL: string; SERVICE: string },
  db: RestClient,
): Promise<Response> {
  const username = String(body.username ?? "").trim().toLowerCase();
  if (!username) return bad(req, "username_required");

  const adminHeaders = { apikey: env.SERVICE, authorization: `Bearer ${env.SERVICE}` };

  // Resolve the Relay account (exact username, case-insensitive via unique idx).
  const profRes = await fetch(
    `${env.SUPABASE_URL}/rest/v1/profiles?username=ilike.${encodeURIComponent(username)}&select=id,username,display_name&limit=1`,
    { headers: adminHeaders, cache: "no-store" },
  );
  const profiles = profRes.ok ? (await profRes.json()) as { id: string; username: string; display_name: string | null }[] : [];
  const profile = profiles[0];
  if (!profile) return bad(req, "unknown_username", 404);

  const destination = `relay:${profile.id}`;

  // Throttle per destination.
  const since = new Date(Date.now() - THROTTLE_WINDOW_MS).toISOString();
  const recent = await db.get<{ id: string }>(
    `auth_challenges?destination=eq.${encodeURIComponent(destination)}&last_sent_at=gte.${since}&select=id`,
  );
  if (recent.rows.length >= MAX_SENDS_PER_DESTINATION) {
    return bad(req, "too_many_sends", 429, { retry_after: 900 });
  }

  // Global per-app ceiling (spam guard across many usernames).
  const appRecent = await db.get<{ id: string }>(
    `auth_challenges?app_id=eq.${encodeURIComponent(app.id)}&last_sent_at=gte.${since}&select=id`,
  );
  if (appRecent.rows.length >= MAX_SENDS_PER_APP) {
    return bad(req, "too_many_sends", 429, { retry_after: 900 });
  }

  const sender = await ensureBusinessSender(app, env, db);
  if (!sender) return bad(req, "sender_unavailable", 503);

  const code = sixDigitCode();
  const ins = await db.post<{ id: string }>(
    "auth_challenges",
    {
      app_id: app.id,
      channel: "relay_dm",
      destination,
      code_hash: await sha256Hex(code),
      ttl_seconds: CODE_TTL_SECONDS,
      attempts: 0,
      expires_at: new Date(Date.now() + CODE_TTL_SECONDS * 1000).toISOString(),
      last_sent_at: new Date().toISOString(),
    },
    true,
  );
  const challenge = ins.rows[0];
  if (!challenge) return bad(req, "challenge_failed", 500);

  // Deliver: DM from the business account into the user's Relay chats.
  const convId = await findOrCreateDirectChat(db, sender.profileId, profile.id, sender);
  if (!convId) return bad(req, "delivery_failed", 502, { challenge_id: challenge.id });

  const text =
    `Your ${sender.displayName} sign-in code is ${code}.\n\n` +
    `It expires in 10 minutes. Never share this code — ${sender.displayName} will never ask for it in a call or another chat.`;
  const msg = await db.post("messages", {
    conversation_id: convId,
    sender_id: sender.profileId,
    message_type: "text",
    content: text,
    send_status: "sent",
  });
  if (!msg.ok) return bad(req, "delivery_failed", 502, { challenge_id: challenge.id });

  // Chat-list freshness + unread badge for the recipient.
  await db.patch(
    `conversations?id=eq.${encodeURIComponent(convId)}`,
    {
      last_message_at: new Date().toISOString(),
      last_message_preview: text.slice(0, 80),
      last_message_sender_id: sender.profileId,
      updated_at: new Date().toISOString(),
    },
  );
  const member = await db.get<{ unread_count: number }>(
    `conversation_members?conversation_id=eq.${encodeURIComponent(convId)}&profile_id=eq.${encodeURIComponent(profile.id)}&select=unread_count&limit=1`,
  );
  const current = member.rows[0]?.unread_count ?? 0;
  await db.patch(
    `conversation_members?conversation_id=eq.${encodeURIComponent(convId)}&profile_id=eq.${encodeURIComponent(profile.id)}`,
    { unread_count: current + 1 },
  );

  return json(req, {
    ok: true,
    challenge_id: challenge.id,
    channel: "relay_dm",
    destination_hint: `@${profile.username}`,
    expires_in: CODE_TTL_SECONDS,
  });
}

// ── POST /auth/otp/verify ────────────────────────────────────────────────────
async function verifyOtp(
  req: Request,
  body: Record<string, unknown>,
  app: { id: string; business_id: string | null },
  env: { SUPABASE_URL: string; SERVICE: string },
  db: RestClient,
): Promise<Response> {
  const challengeId = String(body.challenge_id ?? "");
  const code = String(body.code ?? "").trim();
  if (!challengeId || !/^\d{4,8}$/.test(code)) return bad(req, "bad_request");

  const chRes = await db.get<{ id: string; destination: string; code_hash: string; attempts: number; expires_at: string; consumed_at: string | null }>(
    `auth_challenges?id=eq.${encodeURIComponent(challengeId)}&app_id=eq.${app.id}&select=id,destination,code_hash,attempts,expires_at,consumed_at&limit=1`,
  );
  const ch = chRes.rows[0];
  if (!ch) return bad(req, "unknown_challenge", 404);
  if (ch.consumed_at) return bad(req, "already_used", 409);
  if (new Date(ch.expires_at).getTime() < Date.now()) return bad(req, "expired", 410);
  if (ch.attempts >= 5) return bad(req, "too_many_attempts", 429);

  // Bump attempts first (fail-closed).
  await db.patch(`auth_challenges?id=eq.${encodeURIComponent(ch.id)}`, { attempts: ch.attempts + 1 });

  const computed = await sha256Hex(code);
  if (!timingSafeEqual(computed, ch.code_hash)) return bad(req, "invalid_code", 401);

  // Consume.
  await db.patch(`auth_challenges?id=eq.${encodeURIComponent(ch.id)}`, { consumed_at: new Date().toISOString() });

  // Resolve the Relay profile behind the destination (relay:<profile_id>).
  const profileId = ch.destination.startsWith("relay:") ? ch.destination.slice(6) : "";
  let username: string | null = null;
  let displayName: string | null = null;
  if (profileId) {
    const prof = await db.get<{ id: string; username: string; display_name: string | null }>(
      `profiles?id=eq.${encodeURIComponent(profileId)}&select=id,username,display_name&limit=1`,
    );
    username = prof.rows[0]?.username ?? null;
    displayName = prof.rows[0]?.display_name ?? username;
  }

  return json(req, {
    ok: true,
    external_id: profileId || `relay:${(await sha256Hex(ch.destination)).slice(0, 24)}`,
    username,
    display_name: displayName,
    channel: "relay_dm",
  });
}
