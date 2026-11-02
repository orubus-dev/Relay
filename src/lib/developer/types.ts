/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Relay developer platform — shared types + constants. Row shapes returned
 * from the RLS-protected tables / security-definer RPCs are cast to these.
 */

export const OAUTH_SCOPES = [
  'identity',
  'profile:read',
  'email:read',
  'messages:send',
  'messages:read',
] as const;
export type RelayScope = (typeof OAUTH_SCOPES)[number];

export const SCOPE_META: Record<RelayScope, { label: string; detail: string }> = {
  identity: {
    label: 'identity',
    detail: 'Know who you are — your Relay user ID and @username. Always requested.',
  },
  'profile:read': {
    label: 'profile:read',
    detail: 'Read your profile — display name, @username and avatar.',
  },
  'email:read': {
    label: 'email:read',
    detail: 'See your email address.',
  },
  'messages:send': {
    label: 'messages:send',
    detail: 'Send encrypted messages on your behalf through the Messaging SDK.',
  },
  'messages:read': {
    label: 'messages:read',
    detail: 'Fetch the encrypted messages addressed to you in this app.',
  },
};

export type BusinessProfile = {
  id: string;
  owner_id: string;
  name: string;
  username: string;
  description: string | null;
  avatar_url: string | null;
  website_url: string | null;
  synced_from: 'genjutsu' | null;
  genjutsu_username: string | null;
  created_at: string;
  updated_at: string;
};

export type DevAppProduct = 'auth' | 'messaging_sdk';
export type DevAppPlatform = 'android' | 'ios' | 'web';

export type DevApp = {
  id: string;
  business_id: string;
  name: string;
  product: DevAppProduct;
  platform: DevAppPlatform;
  package_name: string | null;
  origins: string[];
  redirect_uris: string[];
  scopes: string[];
  client_id: string;
  is_active: boolean;
  last_secret_rotated_at: string | null;
  created_at: string;
};

export type SecretGrant = { client_id: string; client_secret: string };

/**
 * Templates are keyed by the request type that consumes them: OTP codes by
 * email (SMTP) or WhatsApp, magic links by email, plus free-form notices.
 */
export type TemplateKind =
  | 'email_otp'
  | 'whatsapp_otp'
  | 'email_magic_link'
  | 'email_notice'
  | 'custom';

export const TEMPLATE_KINDS: {
  value: TemplateKind;
  label: string;
  helper: string;
  usesTtl: boolean;
}[] = [
  { value: 'email_otp', label: 'Email OTP code', helper: 'Sent over our SMTP when your backend calls POST /v1/auth/otp with channel "email" — the user types the {{code}} into your app.', usesTtl: true },
  { value: 'whatsapp_otp', label: 'WhatsApp OTP code', helper: 'Sent over WhatsApp when your backend calls POST /v1/auth/otp with channel "whatsapp".', usesTtl: true },
  { value: 'email_magic_link', label: 'Email magic link', helper: 'Sent over our SMTP when your backend calls POST /v1/auth/magic-link — the user taps the {{link}} to sign in.', usesTtl: true },
  { value: 'email_notice', label: 'Email notice', helper: 'Free-form email from your business (account updates and similar).', usesTtl: false },
  { value: 'custom', label: 'Custom', helper: 'Spare template for anything else.', usesTtl: false },
];

export type DevTemplate = {
  id: string;
  business_id: string;
  kind: TemplateKind;
  name: string;
  subject: string;
  body: string;
  ttl_seconds: number;
  is_active: boolean;
  created_at: string;
};

export const TEMPLATE_TTL_MIN = 30;
export const TEMPLATE_TTL_MAX = 3600;
export const TEMPLATE_TTL_DEFAULT = 60;

export const TEMPLATE_PLACEHOLDERS = [
  { token: '{{username}}', sample: 'orubus', description: "Recipient's @username" },
  { token: '{{business}}', sample: 'Konoha Corp', description: 'Your business display name' },
  { token: '{{code}}', sample: '482913', description: 'One-time code (OTP templates)' },
  { token: '{{link}}', sample: 'https://relayid.pages.dev/v1/auth/magic-link/…', description: 'Sign-in link (magic link templates)' },
  { token: '{{ttl}}', sample: '60', description: 'Lifetime of the code or link, in seconds' },
] as const;

export const SDK_PACKAGE = '@relay/messaging-sdk';
export const API_BASE = 'https://relayid.pages.dev/v1';
