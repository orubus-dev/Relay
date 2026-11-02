/**
 * Google sign-in via Supabase.
 * Native: open hosted login / OAuth URL in Capacitor Browser (in-app Custom Tab),
 * then complete via relay://login deep link — stays in-app, no full external Chrome hop.
 */

import { supabase } from '../lib/supabase/client';

const metaEnv = (import.meta as any).env || {};

export const GOOGLE_WEB_CLIENT_ID =
  metaEnv.VITE_GOOGLE_WEB_CLIENT_ID ||
  metaEnv.NEXT_PUBLIC_GOOGLE_WEB_CLIENT_ID ||
  (typeof process !== 'undefined'
    ? process.env.WEB_CLIENT_ID || process.env.VITE_GOOGLE_WEB_CLIENT_ID
    : '') ||
  '';

export function getPublicWebOrigin(): string {
  const fromEnv =
    metaEnv.VITE_RELAY_WEB_URL ||
    metaEnv.VITE_PUBLIC_WEB_URL ||
    metaEnv.NEXT_PUBLIC_SITE_URL ||
    '';
  if (fromEnv) return String(fromEnv).replace(/\/$/, '');
  if (typeof window !== 'undefined' && window.location?.origin?.startsWith('http')) {
    const origin = window.location.origin;
    if (!origin.includes('localhost') && origin.startsWith('https://')) return origin;
  }
  return 'https://relay-orubus.pages.dev';
}

export function getAuthRedirectUrl(): string {
  if (typeof window === 'undefined') return `${getPublicWebOrigin()}/login`;
  const Cap = (window as any).Capacitor;
  const isNative = !!Cap?.isNativePlatform?.();
  return `${getPublicWebOrigin()}/login${isNative ? '?native=1' : ''}`;
}

export async function initializeGoogleAuth(): Promise<void> {
  // Session handoff is handled by nativeBridge + deep link relay://login
}

/** Open URL inside the app (Custom Tab / SFSafariViewController) — feels in-app. */
async function openInAppBrowser(url: string): Promise<void> {
  const Cap = typeof window !== 'undefined' ? (window as any).Capacitor : null;
  if (Cap?.isNativePlatform?.()) {
    try {
      const mod: any = await import(/* @vite-ignore */ '@capacitor/browser');
      await mod.Browser.open({
        url,
        presentationStyle: 'fullscreen',
        toolbarColor: '#0f172a',
      });
      return;
    } catch {
      /* plugin missing — fall through */
    }
    try {
      if (Cap.Plugins?.Browser?.open) {
        await Cap.Plugins.Browser.open({ url, presentationStyle: 'fullscreen' });
        return;
      }
    } catch {
      /* fall through */
    }
    // Same-WebView navigation keeps the user inside Relay
    try {
      window.location.assign(url);
      return;
    } catch {
      /* fall through */
    }
  }
  if (typeof window !== 'undefined') {
    window.location.assign(url);
  }
}

export async function performNativeGoogleSignIn(): Promise<{
  success: boolean;
  error?: string;
  user?: any;
}> {
  try {
    const Cap = typeof window !== 'undefined' ? (window as any).Capacitor : null;
    const isNative = !!Cap?.isNativePlatform?.();

    if (isNative) {
      // Hosted login page handles Google OAuth with a valid HTTPS redirect,
      // then posts tokens back via relay://login — all from in-app Browser.
      const webLogin = `${getPublicWebOrigin()}/login?native=1&provider=google`;
      await openInAppBrowser(webLogin);
      return { success: true };
    }

    const redirectTo = getAuthRedirectUrl();
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo,
        skipBrowserRedirect: true,
        queryParams: { access_type: 'offline', prompt: 'select_account' },
      },
    });

    if (error) {
      return { success: false, error: error.message };
    }

    if (data?.url) {
      await openInAppBrowser(data.url);
    }

    return { success: true };
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Google Sign-In failed. Please try again.',
    };
  }
}
