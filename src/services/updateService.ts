/**
 * App update checker — progress + idempotent download.
 * Reads latest version from public JSON (Vercel) or GitHub releases.
 */
import { RELAY_WEB_VERSION } from "../lib/version";

const CURRENT = (import.meta as any).env?.VITE_APP_VERSION || RELAY_WEB_VERSION;
const CHECK_URL =
  (import.meta as any).env?.VITE_UPDATE_CHECK_URL ||
  "https://relay-orubus.pages.dev/version.json";
const DOWNLOAD_LOCK_KEY = "relay_update_download_lock";

export type UpdateInfo = {
  current: string;
  latest: string;
  hasUpdate: boolean;
  notes?: string;
  apkUrl?: string;
  force?: boolean;
};

export type DownloadProgress = {
  phase: "idle" | "checking" | "downloading" | "done" | "error";
  percent: number;
  message: string;
};

function cmpSemver(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

export async function checkForUpdates(): Promise<UpdateInfo> {
  try {
    const res = await fetch(`${CHECK_URL}?t=${Date.now()}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const latest = String(data.version || data.latest || CURRENT);
    return {
      current: CURRENT,
      latest,
      hasUpdate: cmpSemver(latest, CURRENT) > 0,
      notes: data.notes || data.changelog,
      apkUrl: data.apkUrl || data.downloadUrl,
      force: !!data.force,
    };
  } catch (e: any) {
    return {
      current: CURRENT,
      latest: CURRENT,
      hasUpdate: false,
      notes: e?.message || "Could not reach update server",
    };
  }
}

/** Idempotent APK download — only one in-flight download at a time. */
export async function downloadUpdate(
  apkUrl: string,
  onProgress?: (p: DownloadProgress) => void
): Promise<{ ok: boolean; error?: string }> {
  if (!apkUrl) return { ok: false, error: "No download URL" };

  try {
    const lock = sessionStorage.getItem(DOWNLOAD_LOCK_KEY);
    if (lock && Date.now() - Number(lock) < 60_000) {
      return { ok: false, error: "Download already in progress" };
    }
    sessionStorage.setItem(DOWNLOAD_LOCK_KEY, String(Date.now()));
  } catch {}

  onProgress?.({ phase: "downloading", percent: 0, message: "Starting download…" });

  try {
    const Cap = typeof window !== "undefined" ? (window as any).Capacitor : null;
    if (Cap?.isNativePlatform?.()) {
      try {
        const mod: any = await import(/* @vite-ignore */ "@capacitor/browser");
        await mod.Browser.open({ url: apkUrl });
        onProgress?.({ phase: "done", percent: 100, message: "Opened download" });
        return { ok: true };
      } catch {
        window.open(apkUrl, "_blank");
        onProgress?.({ phase: "done", percent: 100, message: "Opened download" });
        return { ok: true };
      }
    }

    const a = document.createElement("a");
    a.href = apkUrl;
    a.download = `relay-${Date.now()}.apk`;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
    onProgress?.({ phase: "done", percent: 100, message: "Download started" });
    return { ok: true };
  } catch (e: any) {
    onProgress?.({ phase: "error", percent: 0, message: e?.message || "Download failed" });
    return { ok: false, error: e?.message || "Download failed" };
  } finally {
    try {
      sessionStorage.removeItem(DOWNLOAD_LOCK_KEY);
    } catch {}
  }
}

export function getCurrentAppVersion(): string {
  return CURRENT;
}
