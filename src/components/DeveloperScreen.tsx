/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * /developer — the Relay developer platform (Google-console style).
 *
 *   become a developer → business profile (create or sync from Genjutsu)
 *   → new app (product: messaging SDK / integrate auth, platform, package
 *     name for mobile, JS origins + redirects for web, scopes)
 *   → copy credentials (secret shown exactly once)
 *   → templates → SDK & API docs → diagnostics.
 *
 * Scroll contract: this screen owns its scrolling. The shell is app-h flex;
 * the header is shrink-0 and the body is flex-1 min-h-0 overflow-y-auto.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle, ArrowLeft, BadgeCheck, Blocks, Check, Copy, Download, FileText, KeyRound,
  Loader2, MessageSquareCode, Plus, RefreshCw, RotateCw, ShieldAlert, Store,
  Terminal, Trash2, Wand2,
} from 'lucide-react';
import { GlassCard, GlassButton } from './GlassUI';
import { DeveloperTab } from './DeveloperTab';
import { useAuthStore } from '../store/authStore';
import {
  clampTtl, createApp, createBusiness, createTemplate, deleteTemplate, fetchMyBusiness,
  listApps, listTemplates, lookupGenjutsuBusiness,
  rotateAppSecret, updateApp,
} from '../lib/developer/api';
import {
  API_BASE, OAUTH_SCOPES, SCOPE_META, SDK_PACKAGE, TEMPLATE_KINDS, TEMPLATE_PLACEHOLDERS,
  TEMPLATE_TTL_DEFAULT, type BusinessProfile, type DevApp, type DevAppPlatform,
  type DevAppProduct, type DevTemplate, type RelayScope, type SecretGrant, type TemplateKind,
} from '../lib/developer/types';

type Tab = 'business' | 'apps' | 'templates' | 'sdk' | 'diagnostics';

const TABS: { id: Tab; label: string; icon: React.FC<{ size?: number; className?: string }> }[] = [
  { id: 'business', label: 'Business', icon: Store },
  { id: 'apps', label: 'Apps', icon: Blocks },
  { id: 'templates', label: 'Templates', icon: FileText },
  { id: 'sdk', label: 'SDK & API', icon: Terminal },
  { id: 'diagnostics', label: 'Diagnostics', icon: ShieldAlert },
];

function copy(text: string): void {
  void navigator.clipboard?.writeText(text).catch(() => {});
}

const MonoValue: React.FC<{ value: string }> = ({ value }) => {
  // never render a literal "undefined" — an empty value shows a placeholder
  const shown = typeof value === 'string' && value.length > 0 ? value : '(unavailable)';
  return (
    <div className="flex items-center gap-2 min-w-0">
      <code className="min-w-0 break-all font-mono text-[11px] text-slate-800 dark:text-slate-100">{shown}</code>
      <button
        type="button"
        onClick={() => copy(shown)}
        className="shrink-0 p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-white/10 text-slate-500 cursor-pointer"
        title="Copy"
      >
        <Copy size={13} />
      </button>
    </div>
  );
};

/** Fenced code sample with a copy button right next to the writing. */
const CodeBlock: React.FC<{ code: string }> = ({ code }) => {
  const [done, setDone] = useState(false);
  return (
    <div className="relative mt-2 rounded-2xl bg-slate-950">
      <button
        type="button"
        onClick={() => {
          copy(code);
          setDone(true);
          window.setTimeout(() => setDone(false), 1500);
        }}
        className="absolute top-2 right-2 z-10 flex items-center gap-1 rounded-lg bg-white/10 px-2 py-1.5 text-[10px] font-bold text-slate-200 hover:bg-white/20 cursor-pointer"
        title="Copy"
      >
        {done ? <Check size={12} /> : <Copy size={12} />} {done ? 'Copied' : 'Copy'}
      </button>
      <pre className="overflow-x-auto p-3 font-mono text-[11px] leading-5 text-emerald-200 whitespace-pre">{code}</pre>
    </div>
  );
};

export const DeveloperScreen: React.FC<{ onBack: () => void }> = ({ onBack }) => {
  const currentUser = useAuthStore((s) => s.currentUser);
  const [business, setBusiness] = useState<BusinessProfile | null | undefined>(undefined);
  const [tab, setTab] = useState<Tab>('business');
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setError(null);
      setBusiness(await fetchMyBusiness());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load developer settings.');
      setBusiness(null);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload, currentUser?.id]);

  return (
    <div className="w-full app-h flex flex-col relative overflow-hidden bg-slate-50 dark:bg-black">
      <div className="shrink-0 z-20 border-b border-slate-200/60 dark:border-white/10 px-2 py-2.5 flex items-center gap-2 bg-white/70 dark:bg-black/60 backdrop-blur-xl">
        <button type="button" onClick={onBack} className="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-white/10 cursor-pointer" aria-label="Back">
          <ArrowLeft size={20} />
        </button>
        <div className="flex-1 min-w-0">
          <h1 className="text-sm font-bold text-slate-900 dark:text-white leading-tight">Developer</h1>
          <p className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
            {business ? `@${business.username} · ${business.name}` : 'Business, apps and the messaging SDK'}
          </p>
        </div>
        <button type="button" onClick={() => void reload()} className="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-white/10 text-slate-500 cursor-pointer" aria-label="Refresh">
          <RefreshCw size={16} />
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-3 py-3 pb-28 space-y-4" style={{ overscrollBehavior: 'contain' }}>
        {error && (
          <div className="rounded-2xl border border-red-300/60 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 px-3 py-2 text-xs text-red-600 dark:text-red-300">
            {error}
          </div>
        )}

        {business === undefined ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 size={22} className="animate-spin text-slate-400" />
          </div>
        ) : business === null ? (
          <NotDeveloper onDone={reload} />
        ) : (
          <>
            <div className="flex items-center gap-2 overflow-x-auto pb-1" style={{ scrollbarWidth: 'none' }}>
              {TABS.map(({ id, label, icon: Icon }) => {
                const active = tab === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setTab(id)}
                    style={active ? { backgroundColor: 'var(--primary-accent, #2563EB)', borderColor: 'var(--primary-accent, #2563EB)' } : {}}
                    className={`py-2 px-3.5 rounded-2xl flex items-center gap-1.5 text-xs font-bold shrink-0 cursor-pointer transition-all border ${
                      active
                        ? 'text-white shadow-md'
                        : 'bg-white/70 dark:bg-white/5 text-slate-600 dark:text-slate-300 border-slate-200/80 dark:border-white/10 hover:bg-white dark:hover:bg-white/10'
                    }`}
                  >
                    <Icon size={14} /> <span>{label}</span>
                  </button>
                );
              })}
            </div>

            {tab === 'business' && (
              <BusinessSection business={business} onChanged={reload} />
            )}
            {tab === 'apps' && <AppsSection business={business} />}
            {tab === 'templates' && <TemplatesSection business={business} />}
            {tab === 'sdk' && <SdkSection business={business} />}
            {tab === 'diagnostics' && <DeveloperTab />}
          </>
        )}
      </div>
    </div>
  );
};

/* ------------------------------ not a developer ---------------------------- */

function NotDeveloper({ onDone }: { onDone: () => Promise<void> }) {
  const [mode, setMode] = useState<'choose' | 'create' | 'sync'>('choose');
  return (
    <GlassCard className="p-5">
      <div className="flex items-center gap-3">
        <span className="flex h-11 w-11 items-center justify-center rounded-2xl text-white" style={{ backgroundColor: 'var(--primary-accent, #2563EB)' }}>
          <Wand2 size={20} />
        </span>
        <div>
          <h2 className="text-base font-bold text-slate-900 dark:text-white">Become a developer</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            One business profile per account. Ship sign-in codes, magic links or messaging through our SDK.
          </p>
        </div>
      </div>

      {mode === 'choose' && (
        <div className="mt-4 grid gap-2">
          <GlassButton onClick={() => setMode('create')} className="justify-center py-3">
            <Plus size={16} /> <span>Create business profile</span>
          </GlassButton>
          <GlassButton onClick={() => setMode('sync')} variant="ghost" className="justify-center py-3">
            <RefreshCw size={16} /> <span>Sync from Genjutsu</span>
          </GlassButton>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
            Already created your business on Genjutsu? Sync it here and it lands pre-filled.
          </p>
        </div>
      )}

      {mode === 'create' && <BusinessForm onDone={onDone} onCancel={() => setMode('choose')} />}
      {mode === 'sync' && <SyncForm onDone={onDone} onCancel={() => setMode('choose')} />}
    </GlassCard>
  );
}

const inputCls =
  'w-full rounded-2xl border border-slate-200/80 dark:border-white/10 bg-white/80 dark:bg-white/5 px-3.5 py-3 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 outline-none focus:border-[var(--primary-accent)]';

function BusinessForm({
  onDone, onCancel, prefill,
}: {
  onDone: () => Promise<void>;
  onCancel: () => void;
  prefill?: { name?: string; description?: string | null; avatar_url?: string | null; genjutsuUsername?: string };
}) {
  const [name, setName] = useState(prefill?.name ?? '');
  const [username, setUsername] = useState('');
  const [description, setDescription] = useState(prefill?.description ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true); setError(null);
    try {
      await createBusiness({
        name: name.trim(),
        username: username.trim().toLowerCase(),
        description: description.trim() || undefined,
        syncedFrom: prefill?.genjutsuUsername ? 'genjutsu' : null,
        genjutsuUsername: prefill?.genjutsuUsername ?? null,
      });
      await onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the business.');
    } finally {
      setBusy(false);
    }
  }

  const valid = name.trim().length >= 2 && /^[a-z0-9_]{2,30}$/.test(username.trim().toLowerCase());
  return (
    <div className="mt-4 space-y-3">
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Business name</label>
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Konoha Corp" className={`mt-1 ${inputCls}`} />
      </div>
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Handle</label>
        <div className="mt-1 flex items-center rounded-2xl border border-slate-200/80 dark:border-white/10 bg-white/80 dark:bg-white/5 focus-within:border-[var(--primary-accent)]">
          <span className="pl-3.5 text-slate-400 text-sm">@</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ''))}
            maxLength={30}
            placeholder="konoha"
            className="flex-1 bg-transparent px-2 py-3 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 outline-none"
          />
        </div>
        <p className="mt-1 text-[10px] text-slate-400">a-z, 0-9, underscore. 2 to 30 characters. Permanent.</p>
      </div>
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Description <span className="font-normal text-slate-400">(optional)</span></label>
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} maxLength={500} placeholder="What does your business build?" className={`mt-1 ${inputCls} resize-y`} />
      </div>
      {error && <p className="text-xs text-red-500">{error}</p>}
      <div className="flex gap-2">
        <GlassButton disabled={!valid || busy} onClick={() => void submit()} className="flex-1 justify-center py-3">
          {busy ? <Loader2 size={16} className="animate-spin" /> : <Check size={16} />} <span>Create business</span>
        </GlassButton>
        <GlassButton variant="ghost" onClick={onCancel} className="justify-center py-3">Cancel</GlassButton>
      </div>
    </div>
  );
}

function SyncForm({ onDone, onCancel }: { onDone: () => Promise<void>; onCancel: () => void }) {
  const [handle, setHandle] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [found, setFound] = useState<Awaited<ReturnType<typeof lookupGenjutsuBusiness>>>(null);

  async function lookup() {
    setBusy(true); setError(null); setFound(null);
    try {
      const info = await lookupGenjutsuBusiness(handle);
      if (!info) setError('No Genjutsu business found for that handle.');
      else setFound(info);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Lookup failed.');
    } finally {
      setBusy(false);
    }
  }

  if (found) {
    const suffixless = found.username.replace(/\.auth$/, '');
    return (
      <BusinessForm
        prefill={{ name: found.name, description: found.description, avatar_url: found.avatar_url, genjutsuUsername: suffixless }}
        onDone={onDone}
        onCancel={onCancel}
      />
    );
  }
  return (
    <div className="mt-4 space-y-3">
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Genjutsu business handle</label>
        <div className="mt-1 flex items-center rounded-2xl border border-slate-200/80 dark:border-white/10 bg-white/80 dark:bg-white/5 focus-within:border-[var(--primary-accent)]">
          <span className="pl-3.5 text-slate-400 text-sm">@</span>
          <input
            value={handle}
            onChange={(e) => setHandle(e.target.value.toLowerCase().replace(/[^a-z0-9_.]/g, ''))}
            maxLength={36}
            placeholder="konoha"
            className="flex-1 bg-transparent px-2 py-3 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 outline-none"
          />
          <span className="pr-3.5 text-slate-400 text-sm">.auth</span>
        </div>
      </div>
      {error && <p className="text-xs text-red-500">{error}</p>}
      <div className="flex gap-2">
        <GlassButton disabled={busy || handle.trim().length < 2} onClick={() => void lookup()} className="flex-1 justify-center py-3">
          {busy ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />} <span>Look up</span>
        </GlassButton>
        <GlassButton variant="ghost" onClick={onCancel} className="justify-center py-3">Cancel</GlassButton>
      </div>
    </div>
  );
}

/* -------------------------------- business --------------------------------- */

function BusinessSection({ business, onChanged }: { business: BusinessProfile; onChanged: () => Promise<void> }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(business.name);
  const [description, setDescription] = useState(business.description ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true); setError(null);
    try {
      const { updateBusiness } = await import('../lib/developer/api');
      await updateBusiness({ name: name.trim(), description: description.trim() || null });
      setEditing(false);
      await onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <GlassCard className="p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
            {business.name} {business.synced_from === 'genjutsu' && <BadgeCheck size={15} className="text-sky-500" />}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            @{business.username}
            {business.genjutsu_username ? ` · synced from Genjutsu (@${business.genjutsu_username.replace(/\.auth$/, '')})` : ''}
          </p>
        </div>
        <GlassButton variant="ghost" onClick={() => setEditing((v) => !v)} className="py-1.5 px-3 text-xs shrink-0">
          {editing ? 'Close' : 'Edit'}
        </GlassButton>
      </div>

      {editing && (
        <div className="mt-4 space-y-3">
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} className={inputCls} />
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} maxLength={500} className={`${inputCls} resize-y`} />
          {error && <p className="text-xs text-red-500">{error}</p>}
          <GlassButton disabled={busy || name.trim().length < 2} onClick={() => void save()} className="justify-center py-2.5">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />} <span>Save</span>
          </GlassButton>
        </div>
      )}
    </GlassCard>
  );
}

/* ----------------------------------- apps ---------------------------------- */

function AppsSection({ business }: { business: BusinessProfile }) {
  const [apps, setApps] = useState<DevApp[] | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [pendingSecret, setPendingSecret] = useState<SecretGrant | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setApps(await listApps(business.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load apps.');
    }
  }, [business.id]);

  useEffect(() => { void reload(); }, [reload]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {apps?.length ?? 0} app{(apps?.length ?? 0) === 1 ? '' : 's'} on @{business.username}
        </p>
        <GlassButton onClick={() => setShowCreate((v) => !v)} className="py-2 px-3.5 text-xs shrink-0">
          <Plus size={14} /> <span>{showCreate ? 'Close' : 'New app'}</span>
        </GlassButton>
      </div>

      {error && <p className="text-xs text-red-500">{error}</p>}

      {apps === null ? (
        <div className="flex justify-center py-10"><Loader2 size={20} className="animate-spin text-slate-400" /></div>
      ) : apps.length === 0 && !showCreate ? (
        <GlassCard className="p-8 text-center">
          <Blocks size={22} className="mx-auto text-slate-400" />
          <p className="mt-2 text-sm font-bold text-slate-700 dark:text-slate-200">No apps yet</p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Create an app to integrate auth with Relay or send messages through the SDK.
          </p>
        </GlassCard>
      ) : (
        apps.map((app) => (
          <AppCard key={app.id} app={app} onChanged={reload} onSecret={setPendingSecret} />
        ))
      )}

      {showCreate && (
        <CreateAppForm
          businessId={business.id}
          onCreated={(grant) => { setShowCreate(false); void reload(); setPendingSecret(grant); }}
        />
      )}

      {pendingSecret && <SecretSheet grant={pendingSecret} onDone={() => setPendingSecret(null)} />}
    </div>
  );
}

function ProductPill({ product }: { product: DevAppProduct }) {
  const isSdk = product === 'messaging_sdk';
  return (
    <span className="rounded-full px-2 py-0.5 text-[10px] font-bold bg-slate-100 dark:bg-white/10 text-slate-600 dark:text-slate-300">
      {isSdk ? 'Messaging SDK' : 'Sign-in codes'}
    </span>
  );
}

function PlatformPill({ platform }: { platform: DevAppPlatform }) {
  return (
    <span className="rounded-full px-2 py-0.5 text-[10px] font-bold bg-slate-100 dark:bg-white/10 text-slate-600 dark:text-slate-300 capitalize">
      {platform}
    </span>
  );
}

const AppCard: React.FC<{
  app: DevApp;
  onChanged: () => Promise<void>;
  onSecret: (grant: SecretGrant) => void;
}> = ({ app, onChanged, onSecret }) => {
  const [busy, setBusy] = useState<'toggle' | 'rotate' | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function toggle() {
    setBusy('toggle'); setError(null);
    try {
      await updateApp(app.id, { isActive: !app.is_active });
      await onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update.');
    } finally {
      setBusy(null);
    }
  }

  async function rotate() {
    setBusy('rotate'); setError(null);
    try {
      const grant = await rotateAppSecret(app.id);
      setConfirmRotate(false);
      onSecret(grant);
      await onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not rotate.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <GlassCard className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-bold text-slate-900 dark:text-white truncate">{app.name}</p>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <ProductPill product={app.product} />
            <PlatformPill platform={app.platform} />
            <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${app.is_active ? 'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-300' : 'bg-slate-100 text-slate-500 dark:bg-white/10 dark:text-slate-400'}`}>
              {app.is_active ? 'Active' : 'Inactive'}
            </span>
          </div>
        </div>
        <GlassButton
          variant="ghost"
          onClick={() => void toggle()}
          disabled={busy !== null}
          className="py-1.5 px-3 text-xs shrink-0"
        >
          {busy === 'toggle' ? <Loader2 size={12} className="animate-spin" /> : app.is_active ? 'Disable' : 'Enable'}
        </GlassButton>
      </div>

      <div className="mt-3 space-y-2">
        <div className="rounded-2xl border border-slate-200/80 dark:border-white/10 px-3 py-2">
          <p className="text-[10px] uppercase tracking-wide text-slate-400 font-bold">client id (public)</p>
          <div className="mt-0.5"><MonoValue value={app.client_id} /></div>
        </div>
        {app.package_name && (
          <div className="rounded-2xl border border-slate-200/80 dark:border-white/10 px-3 py-2">
            <p className="text-[10px] uppercase tracking-wide text-slate-400 font-bold">package name</p>
            <div className="mt-0.5"><MonoValue value={app.package_name} /></div>
          </div>
        )}
        {app.platform === 'web' && (
          <div className="rounded-2xl border border-slate-200/80 dark:border-white/10 px-3 py-2">
            <p className="text-[10px] uppercase tracking-wide text-slate-400 font-bold">
              {app.product === 'auth' ? 'authorized JavaScript origins + redirect URIs' : 'redirect URIs'}
            </p>
            <div className="mt-0.5 space-y-0.5">
              {[...app.origins, ...app.redirect_uris].map((uri) => (
                <MonoValue key={uri} value={uri} />
              ))}
            </div>
          </div>
        )}
        <div className="flex flex-wrap gap-1.5">
          {app.scopes.map((s) => (
            <span key={s} className="rounded-full bg-slate-100 dark:bg-white/10 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300">{s}</span>
          ))}
        </div>
      </div>

      {error && <p className="mt-2 text-xs text-red-500">{error}</p>}

      <GlassButton
        variant="ghost"
        disabled={busy !== null}
        onClick={() => setConfirmRotate(true)}
        className="mt-3 py-2 px-3 text-xs text-amber-600 dark:text-amber-300"
      >
        <RotateCw size={12} /> <span>Rotate secret</span>
      </GlassButton>

      {confirmRotate && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true">
          <GlassCard className="p-5 w-full max-w-sm">
            <p className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <AlertTriangle size={16} className="text-amber-500" /> Rotate the secret?
            </p>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              The current secret stops working immediately. Servers using it will fail until you deploy the new one. The new secret is shown once.
            </p>
            <div className="mt-4 flex gap-2">
              <GlassButton variant="danger" onClick={() => void rotate()} className="flex-1 justify-center py-2.5">
                {busy === 'rotate' ? <Loader2 size={14} className="animate-spin" /> : <RotateCw size={14} />} <span>Rotate now</span>
              </GlassButton>
              <GlassButton variant="ghost" onClick={() => setConfirmRotate(false)} className="flex-1 justify-center py-2.5">Cancel</GlassButton>
            </div>
          </GlassCard>
        </div>
      )}
    </GlassCard>
  );
}

function CreateAppForm({ businessId, onCreated }: {
  businessId: string;
  onCreated: (grant: SecretGrant) => void;
}) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState('');
  const [product, setProduct] = useState<DevAppProduct>('auth');
  const [platform, setPlatform] = useState<DevAppPlatform>('web');
  const [packageName, setPackageName] = useState('');
  const [scopes, setScopes] = useState<RelayScope[]>(['identity']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const packageValid = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/i.test(packageName.trim());
  const isMobile = platform !== 'web';
  const fieldsValid = isMobile ? packageValid : true;
  const valid = name.trim().length >= 2 && fieldsValid;

  function toggleScope(scope: RelayScope) {
    setScopes((prev) => {
      const has = prev.includes(scope);
      if (scope === 'identity') return prev;
      if (has) return prev.filter((s) => s !== scope);
      return [...prev, scope];
    });
  }

  async function submit() {
    setBusy(true); setError(null);
    try {
      const grant = await createApp({
        businessId,
        name: name.trim(),
        product,
        platform,
        packageName: isMobile ? packageName.trim() : null,
        origins: [],
        redirectUris: [],
        scopes,
      });
      onCreated(grant);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the app.');
      setBusy(false);
    }
  }

  return (
    <GlassCard className="p-5">
      <p className="text-xs font-bold uppercase tracking-wider text-slate-400">New app · step {Math.min(step, 3)} of 3</p>

      {step === 1 && (
        <div className="mt-3 space-y-3">
          <div>
            <label className="text-xs font-bold text-slate-600 dark:text-slate-300">App name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Konoha Notes" className={`mt-1 ${inputCls}`} />
          </div>
          <div>
            <label className="text-xs font-bold text-slate-600 dark:text-slate-300">What will this app do?</label>
            <div className="mt-1.5 grid gap-2">
              {([
                { id: 'auth' as DevAppProduct, icon: KeyRound, title: 'Sign-in codes & magic links', body: 'Your backend calls /v1/auth/otp and /v1/auth/magic-link — we render your templates and deliver by email (SMTP) or WhatsApp. You paste the secrets in, we handle the rest.' },
                { id: 'messaging_sdk' as DevAppProduct, icon: MessageSquareCode, title: 'Messaging SDK', body: 'Drop our SDK into your app, VPS or backend. We handle the encryption end to end.' },
              ]).map(({ id, icon: Icon, title, body }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setProduct(id)}
                  className={`flex items-start gap-3 rounded-2xl border px-3.5 py-3 text-left cursor-pointer transition-all ${
                    product === id
                      ? 'border-[var(--primary-accent)] bg-[color-mix(in_srgb,var(--primary-accent)_8%,transparent)]'
                      : 'border-slate-200/80 dark:border-white/10 hover:bg-white/60 dark:hover:bg-white/5'
                  }`}
                >
                  <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-slate-100 dark:bg-white/10 text-slate-600 dark:text-slate-300">
                    <Icon size={15} />
                  </span>
                  <span className="min-w-0">
                    <span className="block text-sm font-bold text-slate-900 dark:text-white">{title}</span>
                    <span className="mt-0.5 block text-[11px] leading-4 text-slate-500 dark:text-slate-400">{body}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
          <GlassButton disabled={name.trim().length < 2} onClick={() => setStep(2)} className="w-full justify-center py-3">
            <span>Next · platform</span>
          </GlassButton>
        </div>
      )}

      {step === 2 && (
        <div className="mt-3 space-y-3">
          <div>
            <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Platform</label>
            <div className="mt-1.5 grid grid-cols-3 gap-2">
              {(['android', 'ios', 'web'] as DevAppPlatform[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setPlatform(p)}
                  style={platform === p ? { backgroundColor: 'var(--primary-accent, #2563EB)' } : {}}
                  className={`rounded-2xl border py-3 text-xs font-bold capitalize cursor-pointer transition-all ${
                    platform === p
                      ? 'text-white border-transparent'
                      : 'border-slate-200/80 dark:border-white/10 text-slate-600 dark:text-slate-300 hover:bg-white/60 dark:hover:bg-white/5'
                  }`}
                >
                  {p === 'ios' ? 'iOS' : p === 'web' ? 'Web app' : 'Android'}
                </button>
              ))}
            </div>
          </div>

          {isMobile && (
            <div>
              <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Add package name</label>
              <input
                value={packageName}
                onChange={(e) => setPackageName(e.target.value.toLowerCase().replace(/[^a-z0-9._]/g, ''))}
                placeholder={platform === 'android' ? 'com.konoha.notes' : 'corp.konoha.notes'}
                className={`mt-1 ${inputCls} font-mono`}
              />
              <p className="mt-1 text-[10px] text-slate-400">
                {platform === 'android' ? 'Android applicationId' : 'iOS bundle identifier'} — must contain at least one dot, like Google Play packages.
              </p>
              {!packageValid && packageName.length > 0 && (
                <p className="mt-1 text-[11px] text-red-500">Needs at least one dot, e.g. com.example.app</p>
              )}
            </div>
          )}

          {!isMobile && (
            <div className="rounded-2xl border border-slate-200/80 dark:border-white/10 bg-white/60 dark:bg-white/5 px-3.5 py-3">
              <p className="text-xs font-bold text-slate-600 dark:text-slate-300">Web app</p>
              <p className="mt-1 text-[11px] leading-5 text-slate-500 dark:text-slate-400">
                Nothing else to configure here — calls go straight to our API with your client id and secret.
                {product === 'auth' ? ' OAuth redirects and authorized domains live on Genjutsu, not Relay.' : ''}
              </p>
            </div>
          )}

          <div className="flex gap-2">
            <GlassButton variant="ghost" onClick={() => setStep(1)} className="justify-center py-3">Back</GlassButton>
            <GlassButton disabled={!fieldsValid} onClick={() => setStep(3)} className="flex-1 justify-center py-3">
              <span>Next · permissions</span>
            </GlassButton>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="mt-3 space-y-3">
          <div>
            <label className="text-xs font-bold text-slate-600 dark:text-slate-300">What the app will request</label>
            <div className="mt-1.5 space-y-2">
              {OAUTH_SCOPES.map((scope) => {
                const locked = scope === 'identity';
                const checked = locked || scopes.includes(scope);
                return (
                  <label
                    key={scope}
                    className={`flex items-start gap-3 rounded-2xl border px-3 py-2.5 cursor-pointer ${
                      checked ? 'border-[var(--primary-accent)] bg-[color-mix(in_srgb,var(--primary-accent)_8%,transparent)]' : 'border-slate-200/80 dark:border-white/10'
                    }`}
                  >
                    <input type="checkbox" checked={checked} disabled={locked} onChange={() => toggleScope(scope)} className="mt-0.5 h-4 w-4 accent-[var(--primary-accent)]" />
                    <span className="min-w-0">
                      <span className="block font-mono text-xs font-bold text-slate-800 dark:text-slate-100">{SCOPE_META[scope].label}</span>
                      <span className="mt-0.5 block text-[11px] leading-4 text-slate-500 dark:text-slate-400">{SCOPE_META[scope].detail}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
          {error && <p className="text-xs text-red-500">{error}</p>}
          <div className="flex gap-2">
            <GlassButton variant="ghost" onClick={() => setStep(2)} className="justify-center py-3">Back</GlassButton>
            <GlassButton disabled={!valid || busy} onClick={() => void submit()} className="flex-1 justify-center py-3">
              {busy ? <Loader2 size={16} className="animate-spin" /> : <Check size={16} />} <span>Create app</span>
            </GlassButton>
          </div>
        </div>
      )}
    </GlassCard>
  );
};

/* ------------------------------ secret sheet ------------------------------- */

function SecretSheet({ grant, onDone }: { grant: SecretGrant; onDone: () => void }) {
  const [ack, setAck] = useState(false);
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4" role="dialog" aria-modal="true" aria-label="App credentials">
      <GlassCard className="p-5 w-full max-w-md">
        <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-300">
          <KeyRound size={20} />
        </span>
        <h2 className="mt-3 text-base font-bold text-slate-900 dark:text-white">Copy your client secret now</h2>
        <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">
          It is stored hashed on our servers and <strong className="text-slate-800 dark:text-slate-100">will never be shown again</strong>. Save it in your secrets manager before continuing.
        </p>
        <div className="mt-4 space-y-2 rounded-2xl border border-slate-200/80 dark:border-white/10 bg-white/70 dark:bg-black/40 p-3">
          <div>
            <p className="text-[10px] uppercase tracking-wide text-slate-400 font-bold">client id</p>
            <MonoValue value={grant.client_id} />
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wide text-slate-400 font-bold">client secret — shown once</p>
            <div className="mt-0.5">
              <MonoValue value={grant.client_secret} />
            </div>
          </div>
        </div>
        <label className="mt-4 flex items-start gap-3 text-xs leading-5 text-slate-500 dark:text-slate-400 cursor-pointer">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5 h-4 w-4 accent-[var(--primary-accent)]" />
          I saved the secret somewhere safe and understand it cannot be viewed again.
        </label>
        <GlassButton disabled={!ack} onClick={onDone} className="mt-3 w-full justify-center py-3">
          <span>I'm done — close forever</span>
        </GlassButton>
      </GlassCard>
    </div>
  );
}

/* -------------------------------- templates -------------------------------- */

function TemplatesSection({ business }: { business: BusinessProfile }) {
  const [templates, setTemplates] = useState<DevTemplate[] | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setTemplates(await listTemplates(business.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load templates.');
    }
  }, [business.id]);

  useEffect(() => { void reload(); }, [reload]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-slate-500 dark:text-slate-400">Email and inbox copy used by your challenges and notifications.</p>
        <GlassButton onClick={() => setShowCreate((v) => !v)} className="py-2 px-3.5 text-xs shrink-0">
          <Plus size={14} /> <span>{showCreate ? 'Close' : 'New'}</span>
        </GlassButton>
      </div>

      {error && <p className="text-xs text-red-500">{error}</p>}

      {templates === null ? (
        <div className="flex justify-center py-10"><Loader2 size={20} className="animate-spin text-slate-400" /></div>
      ) : templates.length === 0 && !showCreate ? (
        <GlassCard className="p-8 text-center">
          <FileText size={22} className="mx-auto text-slate-400" />
          <p className="mt-2 text-sm font-bold text-slate-700 dark:text-slate-200">No templates yet</p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">One per request type — email OTP, WhatsApp OTP, magic link.</p>
        </GlassCard>
      ) : (
        templates.map((t) => (
          <GlassCard key={t.id} className="p-4">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="text-sm font-bold text-slate-900 dark:text-white truncate">{t.name}</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  {TEMPLATE_KINDS.find((k) => k.value === t.kind)?.label ?? t.kind}
                  {TEMPLATE_KINDS.find((k) => k.value === t.kind)?.usesTtl ? ` · expires after ${t.ttl_seconds}s` : ''}
                  {t.is_active ? '' : ' · inactive'}
                </p>
              </div>
              <GlassButton variant="ghost" onClick={() => void deleteTemplate(t.id).then(reload)} className="py-1.5 px-2.5 text-xs text-red-500 shrink-0" aria-label="Delete template">
                <Trash2 size={13} />
              </GlassButton>
            </div>
            {t.subject && <p className="mt-2 text-xs font-semibold text-slate-700 dark:text-slate-200 break-words">{t.subject}</p>}
            <p className="mt-1 text-[11px] leading-5 text-slate-500 dark:text-slate-400 whitespace-pre-wrap break-words line-clamp-4">{t.body}</p>
          </GlassCard>
        ))
      )}

      {showCreate && (
        <GlassCard className="p-5">
          <TemplateForm businessId={business.id} businessName={business.name} onCreated={() => { setShowCreate(false); void reload(); }} />
        </GlassCard>
      )}
    </div>
  );
}

const TEMPLATE_DEFAULTS: Record<TemplateKind, { name: string; subject: string; body: string; ttl: number }> = {
  email_otp: {
    name: 'Email OTP (default)',
    subject: `{{code}} is your ${'{{business}}'} sign-in code`,
    body: `Hi {{username}},\n\nYour verification code is {{code}}. It expires after {{ttl}} seconds.\n\n— ${'{{business}}'}`,
    ttl: 60,
  },
  whatsapp_otp: {
    name: 'WhatsApp OTP (default)',
    subject: '',
    body: `${'{{business}}'}: your verification code is {{code}}. It expires after {{ttl}} seconds.`,
    ttl: 60,
  },
  email_magic_link: {
    name: 'Magic link (default)',
    subject: `Your ${'{{business}}'} sign-in link`,
    body: `Hi,\n\nTap this link to sign in. It works once and expires after {{ttl}} seconds:\n\n{{link}}\n\n— ${'{{business}}'}`,
    ttl: 900,
  },
  email_notice: {
    name: 'Email notice (default)',
    subject: `An update from ${'{{business}}'}`,
    body: `Hi {{username}},\n\n…\n\n— ${'{{business}}'}`,
    ttl: 60,
  },
  custom: {
    name: 'Custom template',
    subject: '',
    body: '',
    ttl: 60,
  },
};

function TemplateForm({ businessId, businessName, onCreated }: {
  businessId: string;
  businessName: string;
  onCreated: () => void;
}) {
  const [kind, setKind] = useState<TemplateKind>('email_otp');
  const [name, setName] = useState(TEMPLATE_DEFAULTS.email_otp.name);
  const [subject, setSubject] = useState(TEMPLATE_DEFAULTS.email_otp.subject);
  const [body, setBody] = useState(TEMPLATE_DEFAULTS.email_otp.body);
  const [ttl, setTtl] = useState(TEMPLATE_DEFAULTS.email_otp.ttl);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const kindMeta = TEMPLATE_KINDS.find((k) => k.value === kind)!;

  function switchKind(next: TemplateKind) {
    setKind(next);
    const d = TEMPLATE_DEFAULTS[next];
    setName(d.name);
    setSubject(d.subject);
    setBody(d.body);
    setTtl(d.ttl);
  }

  async function submit() {
    setBusy(true); setError(null);
    try {
      await createTemplate(businessId, { kind, name: name.trim(), subject, body, ttlSeconds: ttl, isActive: true });
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the template.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-sm font-bold text-slate-900 dark:text-white">New template</p>
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Request type</label>
        <select value={kind} onChange={(e) => switchKind(e.target.value as TemplateKind)} className={`mt-1 ${inputCls}`}>
          {TEMPLATE_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
        </select>
        <p className="mt-1 text-[10px] text-slate-400">{kindMeta.helper}</p>
      </div>
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Name <span className="font-normal text-slate-400">(only you see this)</span></label>
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Sign-in code (default)" className={`mt-1 ${inputCls}`} />
      </div>
      {kind !== 'whatsapp_otp' && (
        <div>
          <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Subject</label>
          <input value={subject} onChange={(e) => setSubject(e.target.value)} maxLength={200} className={`mt-1 ${inputCls}`} />
        </div>
      )}
      <div>
        <label className="text-xs font-bold text-slate-600 dark:text-slate-300">Body</label>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={5} maxLength={5000} className={`mt-1 ${inputCls} resize-y`} />
      </div>
      {kindMeta.usesTtl && (
        <div>
          <label className="text-xs font-bold text-slate-600 dark:text-slate-300">
            Code lifetime — {ttl}s <span className="font-normal text-slate-400">(30 to 3600, default 60)</span>
          </label>
          <input type="range" min={30} max={3600} step={30} value={ttl} onChange={(e) => setTtl(Number(e.target.value))} className="mt-1 w-full accent-[var(--primary-accent)]" />
        </div>
      )}
      <div className="rounded-2xl border border-slate-200/80 dark:border-white/10 bg-white/60 dark:bg-white/5 p-3">
        <p className="text-[10px] uppercase tracking-wide text-slate-400 font-bold mb-1">Preview</p>
        {kind !== 'whatsapp_otp' && <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">{renderPreview(subject, businessName)}</p>}
        <p className="mt-1 text-[11px] leading-5 text-slate-500 dark:text-slate-400 whitespace-pre-wrap">{renderPreview(body, businessName)}</p>
      </div>
      <p className="text-[10px] text-slate-400">
        Placeholders: {TEMPLATE_PLACEHOLDERS.map((p) => p.token).join(' · ')}
      </p>
      {error && <p className="text-xs text-red-500">{error}</p>}
      <GlassButton disabled={busy || name.trim().length < 1 || body.trim().length < 1} onClick={() => void submit()} className="w-full justify-center py-3">
        {busy ? <Loader2 size={16} className="animate-spin" /> : <Check size={16} />} <span>Create template</span>
      </GlassButton>
    </div>
  );
}

function renderPreview(text: string, businessName: string): string {
  return text
    .replaceAll('{{username}}', 'orubus')
    .replaceAll('{{business}}', businessName)
    .replaceAll('{{code}}', '482913')
    .replaceAll('{{link}}', 'https://relayid.pages.dev/v1/auth/magic-link/…')
    .replaceAll('{{ttl}}', '60');
}

/* -------------------------------- SDK & API -------------------------------- */

function SdkSection({ business }: { business: BusinessProfile }) {
  const sdkApps = [
    { id: 'a', title: 'Install', code: `import { RelayClient } from './relay-sdk.mjs';

// one file, zero dependencies — browser, Node, Deno or Bun.
// X3DH + Double Ratchet are bundled inside.`, body: 'Download the client below and drop it into your project. Everything the protocol needs travels in that one file.' },
    {
      id: 'b',
      title: 'Connect your users',
      code: `import { RelayClient } from './relay-sdk.mjs';

const relay = new RelayClient({
  appId: 'rl_your_app_id',
  baseUrl: '${API_BASE}',
});

// your backend mints a short-lived user token:
const token = await fetch('/your-api/relay-token', {
  method: 'POST',
  body: JSON.stringify({ externalId: 'user_42' }),
});
await relay.connectWithToken(await token.text());`,
      body: 'We handle identity. Your users keep their own ids — the SDK maps them to Relay encryption keys automatically.',
    },
    {
      id: 'c',
      title: 'Send a message (Signal-level encryption)',
      code: `// first send runs X3DH against your peer's prekey bundle,
// every message after rides the Double Ratchet:
const receipt = await relay.send('user_43', 'See you at the checkpoint');
// forward secrecy + break-in recovery + tamper rejection, all in the SDK.
// Relay only ever stores public bundles and ciphertext.`,
      body: 'Keys are generated on the device. The gateway is the hidden plumber: it routes envelopes and prekey bundles and never sees a private key or a word of plaintext.',
    },
    {
      id: 'd',
      title: 'Receive',
      code: `const inbox = await relay.inbox();        // fetch + decrypt in one call
for (const m of inbox) console.log(m.from, m.text);
await relay.markRead(inbox.map((m) => m.id));

// or handle envelopes yourself (throws on tamper/replay):
const { messages } = await relay.messages();
for (const m of messages) console.log(await relay.decrypt(m));`,
      body: 'Out-of-order delivery, replays and tampering are handled inside the SDK — the ratchet rolls back cleanly instead of desyncing. Poll on an interval or on push.',
    },
    {
      id: 'e',
      title: 'Your backend tables (optional)',
      code: `-- mirror what you need on your side; Relay keeps the full record
create table relay_receipts (
  relay_message_id uuid primary key,
  sender_external_id text not null,
  recipient_external_id text not null,
  created_at timestamptz not null default now()
);`,
      body: 'Add the tables you need on your own database and store receipts, threads or flags. Relay holds identity bundles and ciphertext envelopes; you hold the product data.',
    },
  ];

  const authEndpoints: [string, string][] = [
    ['otp send', `${API_BASE}/auth/otp`],
    ['otp verify', `${API_BASE}/auth/otp/verify`],
    ['magic link', `${API_BASE}/auth/magic-link`],
  ];

  return (
    <div className="space-y-3">
      <GlassCard className="p-5">
        <p className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <MessageSquareCode size={16} /> Relay Messaging SDK
        </p>
        <p className="mt-1.5 text-xs leading-5 text-slate-500 dark:text-slate-400">
          Signal-level E2EE messaging: X3DH key agreement with signed prekeys, a Double Ratchet on every
          message (forward secrecy + break-in recovery), AES-256-GCM via WebCrypto. Private keys are
          generated on your user&apos;s device and never leave it — the gateway relays public bundles and
          ciphertext, nothing more.
        </p>
        <div className="mt-3 grid grid-cols-2 gap-2">
          <a
            href="/sdk/relay-sdk.mjs"
            download="relay-sdk.mjs"
            className="flex items-center justify-center gap-2 rounded-2xl px-3 py-2.5 text-xs font-bold text-white cursor-pointer"
            style={{ backgroundColor: 'var(--primary-accent, #2563EB)' }}
          >
            <Download size={14} /> <span>Download client</span>
          </a>
          <a
            href="/sdk/relay-server.mjs"
            download="relay-server.mjs"
            className="flex items-center justify-center gap-2 rounded-2xl border border-slate-200/80 dark:border-white/10 px-3 py-2.5 text-xs font-bold text-slate-600 dark:text-slate-200 hover:bg-white/60 dark:hover:bg-white/5 cursor-pointer"
          >
            <Download size={14} /> <span>Download server</span>
          </a>
        </div>
        <p className="mt-2 text-[10px] text-slate-400">
          Prebuilt ES modules — import <code className="font-mono">RelayClient</code> from the client bundle in the
          browser, <code className="font-mono">RelayServer</code> from the server bundle on your backend to mint user
          tokens. Same code as the npm package.
        </p>
      </GlassCard>

      {sdkApps.map((s) => (
        <GlassCard key={s.id} className="p-4">
          <p className="text-sm font-bold text-slate-900 dark:text-white">{s.title}</p>
          <p className="mt-1 text-[11px] leading-5 text-slate-500 dark:text-slate-400">{s.body}</p>
          <CodeBlock code={s.code} />
        </GlassCard>
      ))}

      <GlassCard className="p-5">
        <p className="text-sm font-bold text-slate-900 dark:text-white">Sign-in endpoints</p>
        <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
          For "Sign-in codes &amp; magic links" apps — POST from your backend with your client id + secret in the body,
          we render your templates and deliver by email (SMTP) or WhatsApp. Everything lives on our domain, never a
          provider URL.
        </p>
        <div className="mt-3 space-y-1.5 font-mono text-[11px]">
          {authEndpoints.map(([label, url]) => (
            <div key={label} className="flex items-center justify-between gap-2 rounded-xl border border-slate-200/80 dark:border-white/10 px-3 py-2">
              <span className="text-slate-400 uppercase text-[9px] font-bold w-20 shrink-0">{label}</span>
              <span className="min-w-0 truncate text-slate-700 dark:text-slate-200">{url}</span>
              <button type="button" onClick={() => copy(url)} className="shrink-0 text-slate-400 hover:text-slate-600 cursor-pointer" title="Copy"><Copy size={12} /></button>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[10px] leading-5 text-slate-400">
          <code className="font-mono">POST {"{ client_id, client_secret, channel: 'email' | 'whatsapp', destination }"}</code>
          {' '}returns a masked destination and challenge id; verify with the 6-digit code to get back a Relay user
          token the SDK accepts. Magic links land on {API_BASE.replace('/v1', '')} and bounce the user to your
          business website after one tap.
        </p>
      </GlassCard>

      <GlassCard className="p-5">
        <p className="text-sm font-bold text-slate-900 dark:text-white">Genjutsu OAuth (separate product)</p>
        <p className="mt-1 text-[11px] leading-5 text-slate-500 dark:text-slate-400">
          "Continue with Genjutsu" sign-in — client secrets, authorized redirects and the account chooser — is built
          on Genjutsu, not here. Create those apps from the Genjutsu developer portal; this page only covers Relay
          sign-in codes and messaging.
        </p>
      </GlassCard>
    </div>
  );
}
