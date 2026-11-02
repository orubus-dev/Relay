/**
 * Shared auth redirect helpers — HTTPS public web login for OAuth + email links.
 * Must be listed in Supabase Auth → Redirect URLs.
 */
const metaEnv = (import.meta as any).env || {};

export function getPublicWebOrigin(): string {
  const fromEnv =
    metaEnv.VITE_RELAY_WEB_URL ||
    metaEnv.VITE_PUBLIC_WEB_URL ||
    metaEnv.NEXT_PUBLIC_SITE_URL ||
    "";
  if (fromEnv) return String(fromEnv).replace(/\/$/, "");
  if (typeof window !== "undefined" && window.location?.origin?.startsWith("http")) {
    const origin = window.location.origin;
    if (!origin.includes("localhost") && origin.startsWith("https://")) return origin;
  }
  return "https://relay-orubus.pages.dev";
}

export function getAuthRedirectUrl(): string {
  if (typeof window === "undefined") return `${getPublicWebOrigin()}/login`;
  const Cap = (window as any).Capacitor;
  const isNative = !!Cap?.isNativePlatform?.();
  return `${getPublicWebOrigin()}/login${isNative ? "?native=1" : ""}`;
}

/** Public invite / share link helpers (must match relay-web routes). */
export function getGroupInviteUrl(tokenOrId: string): string {
  return `${getPublicWebOrigin()}/g/${encodeURIComponent(tokenOrId)}`;
}

export function getCommunityInviteUrl(tokenOrHandle: string): string {
  return `${getPublicWebOrigin()}/c/${encodeURIComponent(tokenOrHandle)}`;
}

export function getChannelInviteUrl(tokenOrId: string): string {
  return `${getPublicWebOrigin()}/channel/${encodeURIComponent(tokenOrId)}`;
}

export function getGenericInviteUrl(token: string): string {
  return `${getPublicWebOrigin()}/invite/${encodeURIComponent(token)}`;
}

/** Shareable contact link — resolves on the real deployed origin (/u/:username). */
export function getContactShareUrl(usernameOrId: string): string {
  return `${getPublicWebOrigin()}/u/${encodeURIComponent(usernameOrId)}`;
}
