"use client";

import { useCallback, useEffect, useState } from "react";

/* ------------------------------------------------------------------ */
/* Types (mirror of admin API responses — metadata only, no secrets)  */
/* ------------------------------------------------------------------ */

interface AppRow {
  id: string;
  appId: string;
  displayName: string;
  status: "active" | "disabled" | "revoked";
  defaultRateLimit: number;
  createdAt: string;
  lastUsedAt: string | null;
  usage: { total: number; failures: number };
}

interface Stats {
  version: string;
  providers: Record<
    string,
    { status: string; capabilities: string[]; keyFingerprint: string | null }
  >;
  totals: {
    applications: number;
    activeApplications: number;
    capabilities: number;
    secrets: number;
    events: number;
    failures: number;
    rateLimited: number;
  };
  perProvider: {
    provider: string | null;
    operation: string | null;
    total: number;
    failures: number;
    rateLimited: number;
    lastUsedAt: string | null;
  }[];
}

interface SecretRow {
  id: string;
  secretName: string;
  providerId: string;
  notes: string;
  enabled: boolean;
  createdAt: string;
  status: string;
  fingerprint: string | null;
  usedBy: string[];
}

interface CapabilityRow {
  capability: string;
  providerId: string;
  operation: string;
  secretName: string;
  secretConfigured: string;
  secretEnabled: boolean;
  config: Record<string, unknown>;
  enabled: boolean;
}

interface CapabilitiesResponse {
  adapters: { providerId: string; operations: string[] }[];
  capabilities: CapabilityRow[];
}

interface AuditRow {
  id: string;
  ts: string;
  actor: string;
  appId: string | null;
  endpoint: string;
  operation: string | null;
  outcome: string;
  httpStatus: number;
  latencyMs: number;
  errorCode: string | null;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as { error?: { message?: string } })?.error?.message ?? `HTTP ${res.status}`);
  return data as T;
}

/* ------------------------------------------------------------------ */

export default function AdminDashboard() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ authenticated: boolean }>("/api/admin/session")
      .then((s) => setAuthed(s.authenticated))
      .catch(() => setAuthed(false));
  }, []);

  if (authed === null) return <Shell><p style={{ color: "#9aa4b2" }}>Loading…</p></Shell>;
  if (!authed) return <Shell><LoginForm onSuccess={() => setAuthed(true)} /></Shell>;
  return (
    <Shell>
      <Dashboard onLogout={async () => {
        await api("/api/admin/logout", { method: "POST", body: "{}" }).catch(() => undefined);
        setAuthed(false);
      }} error={error} setError={setError} />
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main style={{ maxWidth: 1040, margin: "0 auto", padding: "40px 24px" }}>
      <header style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, margin: 0 }}>
          KRYPTOS <span style={{ color: "#5b9dff" }}>Broker</span>
        </h1>
        <span style={{ color: "#5b6472", fontSize: 13 }}>operator console</span>
      </header>
      {children}
    </main>
  );
}

function LoginForm({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <form
      style={card}
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          await api("/api/admin/login", { method: "POST", body: JSON.stringify({ username, password }) });
          onSuccess();
        } catch (err) {
          setError(err instanceof Error ? err.message : "Login failed");
        } finally {
          setBusy(false);
        }
      }}
    >
      <h2 style={h2}>Administrator sign in</h2>
      <label style={label}>Username</label>
      <input style={input} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
      <label style={label}>Password</label>
      <input style={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      {error && <p style={{ color: "#ff7b72", fontSize: 13 }}>{error}</p>}
      <button style={btnPrimary} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  );
}

function Dashboard({ onLogout, error, setError }: { onLogout: () => void; error: string | null; setError: (e: string | null) => void }) {
  const [tab, setTab] = useState<"overview" | "secrets" | "capabilities" | "apps" | "create" | "audit">("overview");
  const [stats, setStats] = useState<Stats | null>(null);
  const [apps, setApps] = useState<AppRow[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [secrets, setSecrets] = useState<SecretRow[]>([]);
  const [caps, setCaps] = useState<CapabilitiesResponse>({ adapters: [], capabilities: [] });
  const [oneShot, setOneShot] = useState<{ appId: string; credential: string } | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const [s, a, ev, sec, capResp] = await Promise.all([
        api<Stats>("/api/admin/stats"),
        api<{ applications: AppRow[] }>("/api/admin/apps"),
        api<{ events: AuditRow[] }>("/api/admin/audit?limit=150"),
        api<{ secrets: SecretRow[] }>("/api/admin/secrets"),
        api<CapabilitiesResponse>("/api/admin/capabilities")
      ]);
      setStats(s);
      setApps(a.applications);
      setAudit(ev.events);
      setSecrets(sec.secrets);
      setCaps(capResp);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    }
  }, [setError]);

  useEffect(() => { refresh(); }, [refresh]);

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); await refresh(); } catch (err) { setError(err instanceof Error ? err.message : "Action failed"); }
  };

  const availablePermissions = caps.capabilities.map((c) => c.capability);

  return (
    <>
      <nav style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
        {(["overview", "secrets", "capabilities", "apps", "create", "audit"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} style={tab === t ? tabActive : tabBtn}>
            {{ overview: "Overview", secrets: "Secrets", capabilities: "Capabilities", apps: "Applications", create: "Create app", audit: "Audit log" }[t]}
          </button>
        ))}
        <span style={{ flex: 1 }} />
        <button onClick={refresh} style={tabBtn}>Refresh</button>
        <button onClick={onLogout} style={tabBtn}>Sign out</button>
      </nav>

      {error && <p style={{ color: "#ff7b72" }}>{error}</p>}

      {oneShot && (
        <div style={{ ...card, borderColor: "#d29922" }}>
          <h3 style={{ marginTop: 0, color: "#d29922" }}>New credential for {oneShot.appId} (shown once)</h3>
          <p style={{ color: "#9aa4b2", fontSize: 13 }}>
            Copy it now and store it in the client application&apos;s own secure config. It is stored here
            only as a hash and can never be retrieved again.
          </p>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <code style={{ ...codebox, flex: 1 }}>{oneShot.credential}</code>
            <button style={btnPrimary} onClick={() => navigator.clipboard.writeText(oneShot.credential)}>Copy</button>
            <button style={tabBtn} onClick={() => setOneShot(null)}>I have saved it</button>
          </div>
        </div>
      )}

      {tab === "overview" && stats && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, marginBottom: 16 }}>
            <Stat label="Applications" value={`${stats.totals.activeApplications}/${stats.totals.applications}`} hint="active/total" />
            <Stat label="Secrets" value={String(stats.totals.secrets)} hint="registered" />
            <Stat label="Capabilities" value={String(stats.totals.capabilities)} hint="registered" />
            <Stat label="Events" value={String(stats.totals.events)} hint="audited" />
            <Stat label="Failures" value={String(stats.totals.failures)} hint="all causes" />
            <Stat label="Rate limited" value={String(stats.totals.rateLimited)} hint="HTTP 429" />
          </div>
          <div style={card}>
            <h3 style={h3}>Providers (derived from capabilities)</h3>
            <table style={table}>
              <thead><tr><Th>Provider</Th><Th>Status</Th><Th>Capabilities</Th><Th>Key fingerprint</Th></tr></thead>
              <tbody>
                {Object.entries(stats.providers).map(([name, p]) => (
                  <tr key={name}>
                    <Td>{name}</Td>
                    <Td><Badge ok={p.status === "configured"}>{p.status.toUpperCase()}</Badge></Td>
                    <Td>{p.capabilities.length ? p.capabilities.join(", ") : "—"}</Td>
                    <Td>{p.keyFingerprint ? <code style={codebox}>{p.keyFingerprint}…</code> : "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={card}>
            <h3 style={h3}>Usage &amp; rate limits</h3>
            {stats.perProvider.length === 0 && <p style={{ color: "#9aa4b2" }}>No provider traffic yet.</p>}
            <table style={table}>
              <thead><tr><Th>Operation</Th><Th>Requests</Th><Th>Failures</Th><Th>429s</Th><Th>Last used</Th></tr></thead>
              <tbody>
                {stats.perProvider.map((r, i) => (
                  <tr key={i}>
                    <Td>{r.operation ?? r.provider ?? "—"}</Td>
                    <Td>{r.total}</Td>
                    <Td>{r.failures}</Td>
                    <Td>{r.rateLimited}</Td>
                    <Td>{r.lastUsedAt ? new Date(r.lastUsedAt).toLocaleString() : "never"}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "secrets" && (
        <SecretsTab secrets={secrets} adapters={caps.adapters} act={act} />
      )}

      {tab === "capabilities" && (
        <CapabilitiesTab caps={caps} secrets={secrets} act={act} />
      )}

      {tab === "apps" && (
        <div style={card}>
          <h3 style={h3}>Applications</h3>
          <table style={table}>
            <thead>
              <tr><Th>App</Th><Th>Status</Th><Th>Rate limit (def)</Th><Th>Requests</Th><Th>Failures</Th><Th>Last used</Th><Th>Actions</Th></tr>
            </thead>
            <tbody>
              {apps.map((a) => (
                <tr key={a.id}>
                  <Td><b>{a.appId}</b><br /><span style={{ color: "#5b6472", fontSize: 12 }}>{a.displayName}</span></Td>
                  <Td><Badge ok={a.status === "active"} warn={a.status === "disabled"}>{a.status.toUpperCase()}</Badge></Td>
                  <Td>{a.defaultRateLimit}/min</Td>
                  <Td>{a.usage.total}</Td>
                  <Td>{a.usage.failures}</Td>
                  <Td>{a.lastUsedAt ? new Date(a.lastUsedAt).toLocaleString() : "never"}</Td>
                  <Td>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {a.status !== "revoked" && (
                        <>
                          {a.status === "active"
                            ? <MiniBtn onClick={() => act(async () => api(`/api/admin/apps/${a.id}`, { method: "PATCH", body: JSON.stringify({ status: "disabled" }) }))}>Disable</MiniBtn>
                            : <MiniBtn onClick={() => act(async () => api(`/api/admin/apps/${a.id}`, { method: "PATCH", body: JSON.stringify({ status: "active" }) }))}>Enable</MiniBtn>}
                          <MiniBtn onClick={() => act(async () => {
                            const r = await api<{ credential: string }>(`/api/admin/apps/${a.id}/rotate`, { method: "POST", body: "{}" });
                            setOneShot({ appId: a.appId, credential: r.credential });
                          })}>Rotate key</MiniBtn>
                          <MiniBtn danger onClick={() => {
                            if (confirm(`Revoke ${a.appId} permanently? Its credentials stop working immediately.`)) {
                              act(async () => api(`/api/admin/apps/${a.id}`, { method: "PATCH", body: JSON.stringify({ status: "revoked" }) }));
                            }
                          }}>Revoke</MiniBtn>
                        </>
                      )}
                      <PermissionsEditor appId={a.id} onSaved={refresh} available={availablePermissions} />
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
          {apps.length === 0 && <p style={{ color: "#9aa4b2" }}>No applications registered yet. Use “Create app”.</p>}
        </div>
      )}

      {tab === "create" && (
        <CreateAppForm
          available={availablePermissions}
          onCreated={(appId, credential) => { setOneShot({ appId, credential }); setTab("apps"); refresh(); }}
          onError={setError}
        />
      )}

      {tab === "audit" && (
        <div style={card}>
          <h3 style={h3}>Security &amp; request audit (latest {audit.length})</h3>
          <table style={table}>
            <thead>
              <tr><Th>Time</Th><Th>Actor</Th><Th>App</Th><Th>Endpoint</Th><Th>Outcome</Th><Th>HTTP</Th><Th>Latency</Th><Th>Error</Th></tr>
            </thead>
            <tbody>
              {audit.map((e) => (
                <tr key={e.id}>
                  <Td style={{ whiteSpace: "nowrap", fontSize: 12 }}>{new Date(e.ts).toLocaleString()}</Td>
                  <Td>{e.actor}</Td>
                  <Td>{e.appId ?? "—"}</Td>
                  <Td style={{ fontSize: 12 }}>{e.endpoint}</Td>
                  <Td><Badge ok={e.outcome === "success"}>{e.outcome.toUpperCase()}</Badge></Td>
                  <Td>{e.httpStatus}</Td>
                  <Td>{e.latencyMs} ms</Td>
                  <Td style={{ fontSize: 12 }}>{e.errorCode ?? ""}</Td>
                </tr>
              ))}
            </tbody>
          </table>
          {audit.length === 0 && <p style={{ color: "#9aa4b2" }}>No events recorded yet.</p>}
        </div>
      )}
    </>
  );
}

function PermissionsEditor({ appId, onSaved, available }: { appId: string; onSaved: () => void; available: string[] }) {
  const [open, setOpen] = useState(false);
  const [perms, setPerms] = useState<{ permission: string; rateLimitPerMinute: number | null }[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    const r = await api<{ permissions: { permission: string; rateLimitPerMinute: number | null }[] }>(`/api/admin/apps/${appId}/permissions`);
    setPerms(r.permissions);
    setOpen(true);
  };

  return (
    <>
      <MiniBtn onClick={load}>Permissions</MiniBtn>
      {open && (
        <div style={modalOverlay} onClick={() => setOpen(false)}>
          <div style={modal} onClick={(e) => e.stopPropagation()}>
            <h3 style={h3}>Permissions</h3>
            {available.length === 0 && <p style={{ color: "#9aa4b2" }}>Loading operation list…</p>}
            {available.map((op) => {
              const cur = perms.find((p) => p.permission === op);
              return (
                <div key={op} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <input
                    type="checkbox"
                    checked={Boolean(cur)}
                    onChange={(e) => {
                      setPerms(e.target.checked
                        ? [...perms, { permission: op, rateLimitPerMinute: null }]
                        : perms.filter((p) => p.permission !== op));
                    }}
                  />
                  <code style={{ flex: 1 }}>{op}</code>
                  <input
                    style={{ ...input, width: 90, margin: 0 }}
                    placeholder="def/min"
                    disabled={!cur}
                    value={cur?.rateLimitPerMinute ?? ""}
                    onChange={(e) => {
                      const v = e.target.value === "" ? null : Number(e.target.value);
                      setPerms(perms.map((p) => p.permission === op ? { ...p, rateLimitPerMinute: Number.isFinite(v as number) ? v : null } : p));
                    }}
                  />
                </div>
              );
            })}
            {err && <p style={{ color: "#ff7b72", fontSize: 13 }}>{err}</p>}
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button style={btnPrimary} disabled={busy} onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api(`/api/admin/apps/${appId}/permissions`, { method: "PUT", body: JSON.stringify({ permissions: perms }) });
                  setOpen(false);
                  onSaved();
                } catch (e2) {
                  setErr(e2 instanceof Error ? e2.message : "Save failed");
                } finally { setBusy(false); }
              }}>{busy ? "Saving…" : "Save"}</button>
              <button style={tabBtn} onClick={() => setOpen(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function CreateAppForm({ available, onCreated, onError }: { available: string[]; onCreated: (appId: string, credential: string) => void; onError: (e: string | null) => void }) {
  const [appId, setAppId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [defaultRateLimit, setDefaultRateLimit] = useState("60");
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  return (
    <form
      style={card}
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        onError(null);
        try {
          const permissions = Object.entries(selected)
            .filter(([, v]) => v)
            .map(([permission]) => ({ permission }));
          const r = await api<{ credential: string }>("/api/admin/apps", {
            method: "POST",
            body: JSON.stringify({
              appId: appId.toUpperCase(),
              displayName,
              defaultRateLimit: Number(defaultRateLimit) || undefined,
              permissions
            })
          });
          onCreated(appId.toUpperCase(), r.credential);
        } catch (err) {
          onError(err instanceof Error ? err.message : "Create failed");
        } finally { setBusy(false); }
      }}
    >
      <h3 style={h2}>Register a new client application</h3>
      <p style={{ color: "#9aa4b2", fontSize: 13 }}>
        Each application gets its own revocable credential. Only a hash is stored — the credential
        will be displayed once after creation.
      </p>
      <label style={label}>Application ID (e.g. MAHOLLA)</label>
      <input style={input} value={appId} onChange={(e) => setAppId(e.target.value.toUpperCase())} pattern="[A-Z][A-Z0-9_]{1,39}" required />
      <label style={label}>Display name</label>
      <input style={input} value={displayName} onChange={(e) => setDisplayName(e.target.value)} required minLength={2} />
      <label style={label}>Default rate limit (requests/minute)</label>
      <input style={input} value={defaultRateLimit} onChange={(e) => setDefaultRateLimit(e.target.value)} inputMode="numeric" />
      <label style={label}>Permissions</label>
      <div style={{ marginBottom: 14 }}>
        {available.map((op) => (
          <label key={op} style={{ display: "flex", gap: 8, alignItems: "center", color: "#c6cdd8", fontSize: 14, marginBottom: 6 }}>
            <input type="checkbox" checked={Boolean(selected[op])} onChange={(e) => setSelected({ ...selected, [op]: e.target.checked })} />
            <code>{op}</code>
          </label>
        ))}
      </div>
      <button style={btnPrimary} disabled={busy}>{busy ? "Creating…" : "Create application & issue credential"}</button>
    </form>
  );
}

function SecretsTab({ secrets, adapters, act }: { secrets: SecretRow[]; adapters: { providerId: string; operations: string[] }[]; act: (fn: () => Promise<unknown>) => Promise<void> }) {
  const [secretName, setSecretName] = useState("");
  const [providerId, setProviderId] = useState(adapters[0]?.providerId ?? "gemini");
  const [notes, setNotes] = useState("");
  return (
    <>
      <div style={card}>
        <h3 style={h3}>Registered secrets (metadata only — values live in the deployment environment)</h3>
        <table style={table}>
          <thead><tr><Th>Name (env var)</Th><Th>Status</Th><Th>Provider</Th><Th>Used by</Th><Th>Enabled</Th><Th>Fingerprint</Th><Th>Actions</Th></tr></thead>
          <tbody>
            {secrets.map((s) => (
              <tr key={s.id}>
                <Td><code>{s.secretName}</code>{s.notes && <div style={{ color: "#5b6472", fontSize: 12 }}>{s.notes}</div>}</Td>
                <Td><Badge ok={s.status === "CONFIGURED"} warn={false}>{s.status}</Badge></Td>
                <Td>{s.providerId}</Td>
                <Td style={{ fontSize: 12 }}>{s.usedBy.length ? s.usedBy.join(", ") : "—"}</Td>
                <Td><Badge ok={s.enabled}>{s.enabled ? "YES" : "NO"}</Badge></Td>
                <Td>{s.fingerprint ? <code style={codebox}>{s.fingerprint}…</code> : "—"}</Td>
                <Td>
                  <div style={{ display: "flex", gap: 6 }}>
                    <MiniBtn onClick={() => act(async () => api(`/api/admin/secrets/${s.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !s.enabled }) }))}>
                      {s.enabled ? "Disable" : "Enable"}
                    </MiniBtn>
                    <MiniBtn danger onClick={() => {
                      if (confirm(`Remove registration for ${s.secretName}? (Its value in the environment is unaffected.)`)) {
                        act(async () => api(`/api/admin/secrets/${s.id}`, { method: "DELETE" }));
                      }
                    }}>Delete</MiniBtn>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
        {secrets.length === 0 && <p style={{ color: "#9aa4b2" }}>No secrets registered.</p>}
      </div>
      <div style={card}>
        <h3 style={h3}>Register secret metadata</h3>
        <p style={{ color: "#9aa4b2", fontSize: 13 }}>
          Add the VALUE first in Vercel → Settings → Environment Variables. Then register the NAME here.
          Raw values are never accepted by this dashboard or stored in the database.
        </p>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "end" }}>
          <div style={{ flex: 2, minWidth: 220 }}>
            <label style={label}>Env var name</label>
            <input style={input} placeholder="MY_WEATHER_API_KEY" value={secretName} onChange={(e) => setSecretName(e.target.value.toUpperCase())} />
          </div>
          <div style={{ flex: 1, minWidth: 160 }}>
            <label style={label}>Provider</label>
            <select style={input} value={providerId} onChange={(e) => setProviderId(e.target.value)}>
              {adapters.map((a) => <option key={a.providerId} value={a.providerId}>{a.providerId}</option>)}
            </select>
          </div>
          <div style={{ flex: 2, minWidth: 200 }}>
            <label style={label}>Notes (optional)</label>
            <input style={input} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="what is this for" />
          </div>
          <button style={btnPrimary} onClick={() => act(async () => {
            await api("/api/admin/secrets", { method: "POST", body: JSON.stringify({ secretName, providerId, notes }) });
            setSecretName(""); setNotes("");
          })}>Register</button>
        </div>
      </div>
    </>
  );
}

function CapabilitiesTab({ caps, secrets, act }: { caps: CapabilitiesResponse; secrets: SecretRow[]; act: (fn: () => Promise<unknown>) => Promise<void> }) {
  const [capability, setCapability] = useState("");
  const [providerId, setProviderId] = useState(caps.adapters[0]?.providerId ?? "gemini");
  const [operation, setOperation] = useState(caps.adapters[0]?.operations[0] ?? "generateText");
  const [secretName, setSecretName] = useState("");
  const [configText, setConfigText] = useState("{}");
  const selectedAdapter = caps.adapters.find((a) => a.providerId === providerId);
  const adapterSecrets = secrets.filter((s) => s.providerId === providerId);
  return (
    <>
      <div style={card}>
        <h3 style={h3}>Capabilities (what applications may request)</h3>
        <table style={table}>
          <thead><tr><Th>Capability</Th><Th>Provider</Th><Th>Operation</Th><Th>Secret ref</Th><Th>Secret status</Th><Th>Enabled</Th><Th>Actions</Th></tr></thead>
          <tbody>
            {caps.capabilities.map((c) => (
              <tr key={c.capability}>
                <Td><code>{c.capability}</code></Td>
                <Td>{c.providerId}</Td>
                <Td>{c.operation}</Td>
                <Td><code style={{ fontSize: 12 }}>{c.secretName}</code></Td>
                <Td><Badge ok={c.secretConfigured === "CONFIGURED" && c.secretEnabled}>{c.secretEnabled ? c.secretConfigured : "DISABLED"}</Badge></Td>
                <Td><Badge ok={c.enabled}>{c.enabled ? "YES" : "NO"}</Badge></Td>
                <Td>
                  <div style={{ display: "flex", gap: 6 }}>
                    <MiniBtn onClick={() => act(async () => api(`/api/admin/capabilities/${encodeURIComponent(c.capability)}`, { method: "PATCH", body: JSON.stringify({ enabled: !c.enabled }) }))}>
                      {c.enabled ? "Disable" : "Enable"}
                    </MiniBtn>
                    <MiniBtn danger onClick={() => {
                      if (confirm(`Delete capability ${c.capability}? Apps authorized for it will get 404.`)) {
                        act(async () => api(`/api/admin/capabilities/${encodeURIComponent(c.capability)}`, { method: "DELETE" }));
                      }
                    }}>Delete</MiniBtn>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
        {caps.capabilities.length === 0 && <p style={{ color: "#9aa4b2" }}>No capabilities registered.</p>}
      </div>
      <div style={card}>
        <h3 style={h3}>Create / replace a capability</h3>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <div style={{ minWidth: 200 }}>
            <label style={label}>Capability name</label>
            <input style={input} placeholder="ai.generate" value={capability} onChange={(e) => setCapability(e.target.value.toLowerCase())} />
          </div>
          <div style={{ minWidth: 160 }}>
            <label style={label}>Provider</label>
            <select style={input} value={providerId} onChange={(e) => { setProviderId(e.target.value); const a = caps.adapters.find((x) => x.providerId === e.target.value); if (a) setOperation(a.operations[0]); }}>
              {caps.adapters.map((a) => <option key={a.providerId} value={a.providerId}>{a.providerId}</option>)}
            </select>
          </div>
          <div style={{ minWidth: 160 }}>
            <label style={label}>Operation</label>
            <select style={input} value={operation} onChange={(e) => setOperation(e.target.value)}>
              {(selectedAdapter?.operations ?? []).map((op) => <option key={op} value={op}>{op}</option>)}
            </select>
          </div>
          <div style={{ minWidth: 220 }}>
            <label style={label}>Secret reference</label>
            <select style={input} value={secretName} onChange={(e) => setSecretName(e.target.value)}>
              <option value="">— select registered secret —</option>
              {adapterSecrets.map((s) => <option key={s.id} value={s.secretName}>{s.secretName} ({s.status})</option>)}
            </select>
          </div>
        </div>
        <label style={label}>Adapter config (JSON — e.g. {`{"baseUrl":"https://api.openweathermap.org","path":"/data/2.5/weather","method":"GET","auth":{"placement":"query","name":"appid"}}`} for http-generic)</label>
        <textarea
          style={{ ...input, minHeight: 90, fontFamily: "monospace" }}
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
        />
        <button style={btnPrimary} onClick={() => act(async () => {
          let config: unknown = {};
          try { config = JSON.parse(configText || "{}"); } catch { throw new Error("config is not valid JSON"); }
          await api("/api/admin/capabilities", { method: "POST", body: JSON.stringify({ capability, providerId, secretName, operation, config }) });
          setCapability(""); setConfigText("{}");
        })}>Save capability</button>
      </div>
    </>
  );
}

/* ---------------------------- styling ---------------------------- */

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div style={{ ...card, margin: 0 }}>
      <div style={{ color: "#5b6472", fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, margin: "6px 0 2px" }}>{value}</div>
      <div style={{ color: "#5b6472", fontSize: 12 }}>{hint}</div>
    </div>
  );
}

function Badge({ ok, warn, children }: { ok?: boolean; warn?: boolean; children: React.ReactNode }) {
  const color = ok ? "#3fb950" : warn ? "#d29922" : "#ff7b72";
  return <span style={{ color, border: `1px solid ${color}`, borderRadius: 4, padding: "1px 8px", fontSize: 11 }}>{children}</span>;
}

function Th({ children }: { children: React.ReactNode }) {
  return <th style={{ textAlign: "left", padding: "6px 10px", color: "#5b6472", fontSize: 12, borderBottom: "1px solid #232a38" }}>{children}</th>;
}
function Td({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <td style={{ padding: "8px 10px", borderBottom: "1px solid #161b26", fontSize: 14, ...style }}>{children}</td>;
}
function MiniBtn({ children, onClick, danger }: { children: React.ReactNode; onClick: () => void; danger?: boolean }) {
  return (
    <button type="button" onClick={onClick} style={{ background: "#161b26", color: danger ? "#ff7b72" : "#c6cdd8", border: "1px solid #232a38", borderRadius: 6, padding: "4px 10px", fontSize: 12, cursor: "pointer" }}>
      {children}
    </button>
  );
}

const card: React.CSSProperties = { background: "#10141d", border: "1px solid #232a38", borderRadius: 10, padding: 20, marginBottom: 16 };
const h2: React.CSSProperties = { marginTop: 0, fontSize: 18 };
const h3: React.CSSProperties = { marginTop: 0, fontSize: 15, color: "#c6cdd8" };
const label: React.CSSProperties = { display: "block", margin: "12px 0 6px", color: "#5b6472", fontSize: 12, textTransform: "uppercase", letterSpacing: 1 };
const input: React.CSSProperties = { width: "100%", boxSizing: "border-box", background: "#0b0e14", border: "1px solid #232a38", borderRadius: 6, color: "#e6e9ef", padding: "9px 12px", fontSize: 14 };
const btnPrimary: React.CSSProperties = { background: "#2563eb", color: "#fff", border: "none", borderRadius: 6, padding: "10px 18px", fontSize: 14, cursor: "pointer", marginTop: 8 };
const tabBtn: React.CSSProperties = { background: "#10141d", color: "#9aa4b2", border: "1px solid #232a38", borderRadius: 6, padding: "7px 14px", fontSize: 13, cursor: "pointer" };
const tabActive: React.CSSProperties = { ...tabBtn, background: "#2563eb", color: "#fff", border: "1px solid #2563eb" };
const table: React.CSSProperties = { width: "100%", borderCollapse: "collapse" };
const codebox: React.CSSProperties = { background: "#0b0e14", border: "1px solid #232a38", borderRadius: 6, padding: "6px 10px", fontSize: 13, wordBreak: "break-all" };
const modalOverlay: React.CSSProperties = { position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50 };
const modal: React.CSSProperties = { ...card, width: 440, maxWidth: "90vw", maxHeight: "80vh", overflow: "auto", margin: 0 };
