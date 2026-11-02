/**
 * Relay Auth challenges — /v1/auth/*
 *
 * The "Integrate auth" product: your backend asks Relay to deliver a sign-in
 * challenge, Relay renders YOUR template and sends it through our SMTP /
 * WhatsApp pipes. You paste your client id + secret, we handle the rest.
 *
 * Routes (path after the function root):
 *   POST auth/otp               {client_id, client_secret, channel,
 *                                destination, username?}
 *                            -> {challenge_id, expires_in, destination}
 *   POST auth/otp/verify        {client_id, client_secret, challenge_id, code}
 *                            -> {ok, token, external_id}
 *   POST auth/magic-link        {client_id, client_secret, destination}
 *                            -> {challenge_id, expires_in}
 *   GET  auth/magic-link/:id    ?token=…  (the link the email carries)
 *                            -> 302 to the business website / success page
 *
 * Codes and tokens are stored hashed. TTLs come from the business template
 * (30-3600 s, default 60 s). Rate limits: 1 send / 30 s, 10 / hour per
 * destination. Verification fails closed after 5 bad attempts.
 */
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearer,
  error,
  json,
  preflight,
  readJson,
  sha256Hex,
  signUserToken,
} from "./relay.ts";

type AppRow = {
  id: string;
  client_id: string;
  client_secret_hash: string | null;
  business_id: string;
  product: string;
  is_active: boolean;
};

type TemplateRow = {
  kind: string;
  subject: string;
  body: string;
  ttl_seconds: number;
  is_active: boolean;
};

type BusinessRow = { name: string; website_url: string | null };

type ChallengeRow = {
  id: string;
  app_id: string;
  channel: string;
  destination: string;
  code_hash: string | null;
  token_hash: string | null;
  ttl_seconds: number;
  attempts: number;
  consumed_at: string | null;
  expires_at: string;
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const WA_RE = /^\+?[1-9]\d{6,14}$/;

function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let s = "";
  for (const b of buf) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function code6(): string {
  const buf = new Uint32Array(6);
  crypto.getRandomValues(buf);
  return Array.from(buf, (n) => n % 10).join("");
}

function maskDestination(d: string, channel: string): string {
  if (channel === "email") {
    const [user, domain] = d.split("@");
    return `${user.slice(0, 2)}${"*".repeat(Math.max(1, user.length - 2))}@${domain}`;
  }
  return `+${"*".repeat(Math.max(4, d.replace(/^\+/, "").length - 3))}${d.slice(-3)}`;
}

function render(text: string, vars: Record<string, string>): string {
  return text
    .replaceAll("{{username}}", vars.username ?? "there")
    .replaceAll("{{business}}", vars.business ?? "Relay")
    .replaceAll("{{code}}", vars.code ?? "")
    .replaceAll("{{link}}", vars.link ?? "")
    .replaceAll("{{ttl}}", vars.ttl ?? "60");
}

/* ------------------------------- providers -------------------------------- */

async function sendEmail(to: string, subject: string, text: string): Promise<void> {
  const key = Deno.env.get("RESEND_API_KEY");
  if (!key) throw new Error("email_provider_not_configured");
  const from = Deno.env.get("RESEND_FROM") ?? "Relay <onboarding@resend.dev>";
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, text }),
  });
  if (!res.ok) throw new Error(`email_send_failed_${res.status}`);
}

async function sendWhatsApp(to: string, text: string): Promise<void> {
  const token = Deno.env.get("WHATSAPP_TOKEN");
  const phoneId = Deno.env.get("WHATSAPP_PHONE_NUMBER_ID");
  if (!token || !phoneId) throw new Error("whatsapp_provider_not_configured");
  const res = await fetch(`https://graph.facebook.com/v21.0/${phoneId}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      to: to.replace(/^\+/, ""),
      type: "text",
      text: { body: text },
    }),
  });
  if (!res.ok) throw new Error(`whatsapp_send_failed_${res.status}`);
}

/* --------------------------------- handler -------------------------------- */

Deno.serve(async (req) => {
  const pf = preflight(req);
  if (pf) return pf;

  const admin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );

  const url = new URL(req.url);
  const rawRoute = url.pathname.split("/auth-challenge/")[1] ?? "";
  // Vercel's /v1/auth/:path* rewrite strips the auth/ prefix; the direct
  // Supabase URL keeps it. Accept both.
  const route = rawRoute.startsWith("auth/") ? rawRoute.slice(5) : rawRoute;
  const publicOrigin = Deno.env.get("PUBLIC_ORIGIN") ?? "https://relayid.pages.dev";

  async function resolveApp(body: { client_id?: string; client_secret?: string }): Promise<AppRow | null> {
    const secret = body.client_secret ?? bearer(req);
    const cid = (body.client_id ?? "").trim();
    if (!secret?.startsWith("rs_") || !cid) return null;
    const { data: app } = await admin
      .from("developer_apps")
      .select("id, client_id, client_secret_hash, business_id, product, is_active")
      .eq("client_id", cid)
      .eq("client_secret_hash", await sha256Hex(secret))
      .eq("is_active", true)
      .maybeSingle<AppRow>();
    return app ?? null;
  }

  try {
    /* ------------------------------ POST auth/otp ------------------------------ */
    if (route === "otp" && req.method === "POST") {
      const body = await readJson<{
        client_id?: string; client_secret?: string;
        channel?: string; destination?: string; username?: string;
      }>(req);
      const app = await resolveApp(body);
      if (!app) return error("invalid_app", 401, "Unknown client_id or client_secret.");

      const channel = body.channel === "whatsapp" ? "whatsapp" : "email";
      const destination = (body.destination ?? "").trim();
      if (channel === "email" && !EMAIL_RE.test(destination)) {
        return error("invalid_destination", 400, "That is not a valid email address.");
      }
      if (channel === "whatsapp" && !WA_RE.test(destination.replace(/[\s()-]/g, ""))) {
        return error("invalid_destination", 400, "That is not a valid WhatsApp number (E.164).");
      }
      const dest = channel === "whatsapp" ? destination.replace(/[\s()-]/g, "") : destination.toLowerCase();

      // rate limits: 30 s resend cooldown, 10/hour per app+destination
      const hourAgo = new Date(Date.now() - 3600_000).toISOString();
      const { count } = await admin
        .from("auth_challenges")
        .select("id", { count: "exact", head: true })
        .eq("app_id", app.id)
        .eq("destination", dest)
        .gt("created_at", hourAgo);
      if ((count ?? 0) >= 10) {
        return error("rate_limited", 429, "Too many codes for this destination — try again later.");
      }
      const { data: recent } = await admin
        .from("auth_challenges")
        .select("last_sent_at")
        .eq("app_id", app.id)
        .eq("destination", dest)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle<{ last_sent_at: string }>();
      if (recent && Date.now() - Date.parse(recent.last_sent_at) < 30_000) {
        return error("rate_limited", 429, "Wait 30 seconds before requesting another code.");
      }

      const kind = channel === "whatsapp" ? "whatsapp_otp" : "email_otp";
      const { data: tpl } = await admin
        .from("developer_templates")
        .select("kind, subject, body, ttl_seconds, is_active")
        .eq("business_id", app.business_id)
        .eq("kind", kind)
        .eq("is_active", true)
        .order("created_at", { ascending: true })
        .limit(1)
        .maybeSingle<TemplateRow>();
      const ttl = Math.min(3600, Math.max(30, tpl?.ttl_seconds ?? 60));
      const { data: biz } = await admin
        .from("developer_businesses")
        .select("name, website_url")
        .eq("id", app.business_id)
        .maybeSingle<BusinessRow>();

      const code = code6();
      const vars = {
        username: (body.username ?? "").trim() || "there",
        business: biz?.name ?? "Relay",
        code,
        ttl: String(ttl),
      };

      if (channel === "email") {
        await sendEmail(
          dest,
          render(tpl?.subject ?? "{{code}} is your {{business}} sign-in code", vars),
          render(
            tpl?.body ??
              "Hi {{username}},\n\nYour verification code is {{code}}. It expires after {{ttl}} seconds.\n\n— {{business}}",
            vars,
          ),
        );
      } else {
        await sendWhatsApp(
          dest,
          render(
            tpl?.body ?? "{{business}}: your verification code is {{code}}. It expires after {{ttl}} seconds.",
            vars,
          ),
        );
      }

      const { data: row, error: insErr } = await admin
        .from("auth_challenges")
        .insert({
          app_id: app.id,
          channel,
          destination: dest,
          code_hash: await sha256Hex(code),
          ttl_seconds: ttl,
          expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
        })
        .select("id")
        .maybeSingle<{ id: string }>();
      if (insErr || !row) return error("challenge_failed", 500, insErr?.message ?? "Could not store the challenge.");

      return json({
        challenge_id: row.id,
        channel,
        destination: maskDestination(dest, channel),
        expires_in: ttl,
      });
    }

    /* --------------------------- POST auth/otp/verify -------------------------- */
    if (route === "otp/verify" && req.method === "POST") {
      const body = await readJson<{
        client_id?: string; client_secret?: string; challenge_id?: string; code?: string;
      }>(req);
      const app = await resolveApp(body);
      if (!app) return error("invalid_app", 401, "Unknown client_id or client_secret.");

      const challengeId = (body.challenge_id ?? "").trim();
      const code = (body.code ?? "").replace(/\D/g, "");
      if (!challengeId || !code) {
        return error("invalid_request", 400, "challenge_id and code are required.");
      }

      const { data: ch } = await admin
        .from("auth_challenges")
        .select("*")
        .eq("id", challengeId)
        .eq("app_id", app.id)
        .maybeSingle<ChallengeRow>();
      if (!ch || ch.channel === "magic_link" || !ch.code_hash) {
        return error("invalid_challenge", 404, "That challenge does not exist.");
      }
      if (ch.consumed_at) return error("already_used", 400, "This code was already used.");
      if (Date.parse(ch.expires_at) < Date.now()) return error("expired", 400, "This code has expired.");
      if (ch.attempts >= 5) return error("too_many_attempts", 429, "Too many wrong attempts — request a new code.");

      if ((await sha256Hex(code)) !== ch.code_hash) {
        await admin
          .from("auth_challenges")
          .update({ attempts: ch.attempts + 1 })
          .eq("id", ch.id);
        return error("wrong_code", 400, "That code is not right.");
      }

      await admin
        .from("auth_challenges")
        .update({ consumed_at: new Date().toISOString() })
        .eq("id", ch.id);

      // hand back the same identity token the messaging SDK accepts
      const ext = ch.destination;
      const token = await signUserToken(
        { cid: app.client_id, ext, exp: Math.floor(Date.now() / 1000) + 86400 },
        app.client_secret_hash!,
      );
      return json({
        ok: true,
        channel: ch.channel,
        external_id: ext,
        token,
        token_type: "Bearer",
        expires_in: 86400,
      });
    }

    /* --------------------------- POST auth/magic-link -------------------------- */
    if (route === "magic-link" && req.method === "POST") {
      const body = await readJson<{
        client_id?: string; client_secret?: string; destination?: string;
      }>(req);
      const app = await resolveApp(body);
      if (!app) return error("invalid_app", 401, "Unknown client_id or client_secret.");

      const destination = (body.destination ?? "").trim().toLowerCase();
      if (!EMAIL_RE.test(destination)) {
        return error("invalid_destination", 400, "Magic links go to email addresses.");
      }

      const hourAgo = new Date(Date.now() - 3600_000).toISOString();
      const { count } = await admin
        .from("auth_challenges")
        .select("id", { count: "exact", head: true })
        .eq("app_id", app.id)
        .eq("destination", destination)
        .gt("created_at", hourAgo);
      if ((count ?? 0) >= 10) {
        return error("rate_limited", 429, "Too many links for this destination — try again later.");
      }

      const { data: tpl } = await admin
        .from("developer_templates")
        .select("kind, subject, body, ttl_seconds, is_active")
        .eq("business_id", app.business_id)
        .eq("kind", "email_magic_link")
        .eq("is_active", true)
        .order("created_at", { ascending: true })
        .limit(1)
        .maybeSingle<TemplateRow>();
      const ttl = Math.min(3600, Math.max(30, tpl?.ttl_seconds ?? 900));
      const { data: biz } = await admin
        .from("developer_businesses")
        .select("name, website_url")
        .eq("id", app.business_id)
        .maybeSingle<BusinessRow>();

      const raw = randomToken();
      const { data: row, error: insErr } = await admin
        .from("auth_challenges")
        .insert({
          app_id: app.id,
          channel: "magic_link",
          destination,
          token_hash: await sha256Hex(raw),
          ttl_seconds: ttl,
          expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
        })
        .select("id")
        .maybeSingle<{ id: string }>();
      if (insErr || !row) return error("challenge_failed", 500, insErr?.message ?? "Could not store the challenge.");

      const link = `${publicOrigin}/v1/auth/magic-link/${row.id}?token=${raw}`;
      const vars = { business: biz?.name ?? "Relay", link, ttl: String(ttl) };
      await sendEmail(
        destination,
        render(tpl?.subject ?? "Your {{business}} sign-in link", vars),
        render(
          tpl?.body ??
            "Hi,\n\nTap this link to sign in. It works once and expires after {{ttl}} seconds:\n\n{{link}}\n\n— {{business}}",
          vars,
        ),
      );

      return json({
        challenge_id: row.id,
        destination: maskDestination(destination, "email"),
        expires_in: ttl,
      });
    }

    /* -------------------------- GET auth/magic-link/:id ------------------------ */
    const magicMatch = /^magic-link\/([0-9a-f-]{36})$/.exec(route);
    if (magicMatch && req.method === "GET") {
      const id = magicMatch[1];
      const token = url.searchParams.get("token") ?? "";
      const fail = (msg: string) =>
        new Response(
          `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;display:grid;place-items:center;min-height:100vh;background:#0b1020;color:#e2e8f0"><div style="text-align:center"><p style="font-size:34px;margin:0">🔗</p><h1 style="font-size:18px">Link not accepted</h1><p style="opacity:.7;font-size:14px">${msg}</p><p style="opacity:.5;font-size:12px">Return to the app and request a new link.</p></div></body>`,
          { status: 400, headers: { "content-type": "text/html; charset=utf-8" } },
        );
      if (!token) return fail("This link is incomplete.");

      const { data: ch } = await admin
        .from("auth_challenges")
        .select("*")
        .eq("id", id)
        .eq("channel", "magic_link")
        .maybeSingle<ChallengeRow>();
      if (!ch || !ch.token_hash) return fail("This link is unknown.");
      if (ch.consumed_at) return fail("This link was already used.");
      if (Date.parse(ch.expires_at) < Date.now()) return fail("This link has expired.");
      if ((await sha256Hex(token)) !== ch.token_hash) return fail("This link is not valid.");

      await admin
        .from("auth_challenges")
        .update({ consumed_at: new Date().toISOString() })
        .eq("id", ch.id);

      const { data: app } = await admin
        .from("developer_apps")
        .select("business_id")
        .eq("id", ch.app_id)
        .maybeSingle<{ business_id: string }>();
      const { data: biz } = await admin
        .from("developer_businesses")
        .select("name, website_url")
        .eq("id", app?.business_id ?? "")
        .maybeSingle<BusinessRow>();

      const target = biz?.website_url && /^https?:\/\//.test(biz.website_url) ? biz.website_url : null;
      if (target) {
        return new Response(null, {
          status: 302,
          headers: { Location: target },
        });
      }
      return new Response(
        `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;display:grid;place-items:center;min-height:100vh;background:#0b1020;color:#e2e8f0"><div style="text-align:center"><p style="font-size:34px;margin:0">✅</p><h1 style="font-size:18px">You're signed in</h1><p style="opacity:.7;font-size:14px">Return to ${biz?.name ?? "the app"} — this link can only be used once.</p></div></body>`,
        { status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
      );
    }

    return error("not_found", 404, `Unknown auth route: ${route || "(root)"}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.endsWith("not_configured")) {
      return error("provider_not_configured", 503,
        msg === "whatsapp_provider_not_configured"
          ? "WhatsApp delivery is not wired up yet — add WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID."
          : "Email delivery is not wired up yet — add RESEND_API_KEY (and optionally RESEND_FROM).");
    }
    if (/^email_send_failed_|^whatsapp_send_failed_/.test(msg)) {
      return error("delivery_failed", 502, "The provider rejected the message — check the destination or try again.");
    }
    return error("internal_error", 500, msg);
  }
});
