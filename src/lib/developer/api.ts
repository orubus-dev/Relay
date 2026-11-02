/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Relay developer platform data layer. Tables are RLS-protected; secrets
 * only ever come back from security-definer RPCs and are shown exactly once.
 */
import { supabase } from '../supabase/client';
import {
  TEMPLATE_TTL_DEFAULT,
  TEMPLATE_TTL_MAX,
  TEMPLATE_TTL_MIN,
  type BusinessProfile,
  type DevApp,
  type DevAppPlatform,
  type DevAppProduct,
  type DevTemplate,
  type SecretGrant,
  type TemplateKind,
} from './types';

function rpcError(err: { message: string } | null, fallback: string): Error {
  return new Error(err?.message || fallback);
}

/* -------------------------------- business -------------------------------- */

export async function fetchMyBusiness(): Promise<BusinessProfile | null> {
  // owner_id filter + owner-only RLS: a business belongs to exactly one
  // account. Signing out (or into another account) can never surface
  // someone else's profile.
  const uid = (await supabase.auth.getUser()).data.user?.id;
  if (!uid) return null;
  const { data, error } = await supabase
    .from('developer_businesses')
    .select('*')
    .eq('owner_id', uid)
    .maybeSingle();
  if (error) throw rpcError(error, 'Could not load your business profile.');
  return (data as BusinessProfile | null) ?? null;
}

export async function createBusiness(input: {
  name: string;
  username: string;
  description?: string;
  syncedFrom?: 'genjutsu' | null;
  genjutsuUsername?: string | null;
}): Promise<BusinessProfile> {
  const { data, error } = await supabase.rpc('developer_create_business', {
    p_name: input.name,
    p_username: input.username,
    p_description: input.description || null,
    p_synced_from: input.syncedFrom ?? null,
    p_genjutsu_username: input.genjutsuUsername ?? null,
  });
  if (error) throw rpcError(error, 'Could not create your business profile.');
  return unwrapRow<BusinessProfile>(data);
}

export async function updateBusiness(changes: {
  name?: string;
  description?: string | null;
  website_url?: string | null;
}): Promise<void> {
  const { error } = await supabase.rpc('developer_update_business', {
    p_name: changes.name ?? null,
    p_description: changes.description ?? undefined,
    p_website_url: changes.website_url ?? undefined,
  });
  if (error) throw rpcError(error, 'Could not save your business profile.');
}

/** Public Genjutsu business lookup — used by "sync from Genjutsu". */
export async function lookupGenjutsuBusiness(
  rawHandle: string,
): Promise<{ name: string; username: string; description: string | null; avatar_url: string | null } | null> {
  const handle = rawHandle.trim().toLowerCase().replace(/\.auth$/, '');
  if (!/^[a-z0-9_]{2,30}$/.test(handle)) throw new Error('That is not a valid Genjutsu business handle.');
  const env = (import.meta as { env?: Record<string, string> }).env ?? {};
  const base = env.VITE_GENJUTSU_URL || 'https://genjustu.pages.dev';
  const key = env.VITE_GENJUTSU_PUBLISHABLE_KEY;
  if (!key) throw new Error('Genjutsu sync is not configured (VITE_GENJUTSU_PUBLISHABLE_KEY missing).');
  const res = await fetch(
    `${base}/rest/v1/business_profiles?username=eq.${encodeURIComponent(handle)}.auth&select=name,username,description,avatar_url&limit=1`,
    { headers: { apikey: key, Authorization: `Bearer ${key}` } },
  );
  if (!res.ok) throw new Error('Could not reach Genjutsu to look up that business.');
  const rows = (await res.json()) as {
    name: string;
    username: string;
    description: string | null;
    avatar_url: string | null;
  }[];
  return rows[0] ?? null;
}

/* ---------------------------------- apps ---------------------------------- */

export async function listApps(businessId: string): Promise<DevApp[]> {
  const { data, error } = await supabase
    .from('developer_apps')
    .select('*')
    .eq('business_id', businessId)
    .order('created_at', { ascending: false });
  if (error) throw rpcError(error, 'Could not load your apps.');
  return (data as DevApp[]) ?? [];
}

/**
 * RPCs that RETURN TABLE(...) are set-returning: PostgREST hands back an
 * array with one row. Unwrap it — the secret sheet needs the row object,
 * not the array (rendering grant.client_id on the array is what produced
 * the infamous "undefined" credentials modal).
 */
function unwrapGrant(data: unknown): SecretGrant {
  const row = (Array.isArray(data) ? data[0] : data) as Partial<SecretGrant> | null;
  if (!row || typeof row.client_id !== 'string' || typeof row.client_secret !== 'string') {
    throw new Error('The server did not return credentials — please try again.');
  }
  return { client_id: row.client_id, client_secret: row.client_secret };
}

function unwrapRow<T>(data: unknown): T {
  return (Array.isArray(data) ? data[0] : data) as T;
}

export async function createApp(input: {
  businessId: string;
  name: string;
  product: DevAppProduct;
  platform: DevAppPlatform;
  packageName?: string | null;
  origins?: string[];
  redirectUris?: string[];
  scopes: string[];
}): Promise<SecretGrant> {
  const { data, error } = await supabase.rpc('developer_create_app', {
    p_business_id: input.businessId,
    p_name: input.name,
    p_product: input.product,
    p_platform: input.platform,
    p_package_name: input.packageName ?? null,
    p_origins: input.origins ?? [],
    p_redirect_uris: input.redirectUris ?? [],
    p_scopes: input.scopes,
  });
  if (error) throw rpcError(error, 'Could not create the app.');
  return unwrapGrant(data);
}

export async function rotateAppSecret(appId: string): Promise<SecretGrant> {
  const { data, error } = await supabase.rpc('developer_rotate_app_secret', {
    p_app_id: appId,
  });
  if (error) throw rpcError(error, 'Could not rotate the secret.');
  return unwrapGrant(data);
}

export async function updateApp(
  appId: string,
  changes: { name?: string; scopes?: string[]; isActive?: boolean },
): Promise<void> {
  const { error } = await supabase.rpc('developer_update_app', {
    p_app_id: appId,
    p_name: changes.name ?? null,
    p_scopes: changes.scopes ?? null,
    p_is_active: changes.isActive ?? null,
  });
  if (error) throw rpcError(error, 'Could not update the app.');
}

/* -------------------------------- templates -------------------------------- */

export function clampTtl(value: number): number {
  if (!Number.isFinite(value)) return TEMPLATE_TTL_DEFAULT;
  return Math.min(TEMPLATE_TTL_MAX, Math.max(TEMPLATE_TTL_MIN, Math.round(value)));
}

export async function listTemplates(businessId: string): Promise<DevTemplate[]> {
  const { data, error } = await supabase
    .from('developer_templates')
    .select('*')
    .eq('business_id', businessId)
    .order('created_at', { ascending: true });
  if (error) throw rpcError(error, 'Could not load your templates.');
  return (data as DevTemplate[]) ?? [];
}

export async function createTemplate(
  businessId: string,
  input: { kind: TemplateKind; name: string; subject: string; body: string; ttlSeconds: number; isActive: boolean },
): Promise<void> {
  const { error } = await supabase.from('developer_templates').insert({
    business_id: businessId,
    kind: input.kind,
    name: input.name,
    subject: input.subject,
    body: input.body,
    ttl_seconds: clampTtl(input.ttlSeconds),
    is_active: input.isActive,
  });
  if (error) throw rpcError(error, 'Could not create the template.');
}

export async function deleteTemplate(templateId: string): Promise<void> {
  const { error } = await supabase.from('developer_templates').delete().eq('id', templateId);
  if (error) throw rpcError(error, 'Could not delete the template.');
}

/* --------------------------- redirect URI validation ----------------------- */

export function validateRedirectUriLine(line: string): string | null {
  const uri = line.trim();
  if (!uri) return 'Redirect URI cannot be empty.';
  if (uri.includes('*')) return 'Wildcards are not allowed — URIs must match exactly.';
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return 'That is not a valid absolute URI.';
  }
  if (parsed.protocol === 'https:') return null;
  if (parsed.protocol === 'http:') {
    if (['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) return null;
    return 'Plain http:// is only allowed for localhost.';
  }
  if (/^[a-z][a-z0-9+.-]*:$/i.test(parsed.protocol)) return null;
  return 'Use https:// or a mobile custom scheme (com.example.app:/callback).';
}

export function parseUriList(text: string): { uris: string[]; errors: string[] } {
  const uris: string[] = [];
  const errors: string[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const err = validateRedirectUriLine(line);
    if (err) errors.push(`"${line.trim()}" — ${err}`);
    else uris.push(line.trim());
  }
  return { uris, errors };
}

export function validateOriginLine(line: string): string | null {
  const origin = line.trim();
  if (!origin) return 'Origin cannot be empty.';
  try {
    const parsed = new URL(origin);
    if (parsed.pathname !== '/' && parsed.pathname !== '') return 'Use a bare origin, no path.';
    if (parsed.protocol === 'https:') return null;
    if (parsed.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(parsed.hostname)) return null;
    return 'Use https:// (http only for localhost).';
  } catch {
    return 'That is not a valid origin, e.g. https://app.example.com';
  }
}

export function parseOriginList(text: string): { origins: string[]; errors: string[] } {
  const origins: string[] = [];
  const errors: string[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const err = validateOriginLine(line);
    if (err) errors.push(`"${line.trim()}" — ${err}`);
    else origins.push(line.trim().replace(/\/$/, ''));
  }
  return { origins, errors };
}
