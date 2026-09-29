import React, { useCallback, useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { Copy, KeyRound, Trash2, UserPlus, AlertTriangle, Check } from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../auth';

const SECTIONS = [
  ['organization', 'Organisation'],
  ['members', 'Members'],
  ['api-keys', 'API keys'],
  ['integrations', 'Integrations'],
  ['data', 'Data & privacy'],
  ['account', 'Your account'],
];

const SENSITIVITY_TEXT = {
  strict: 'Blocks more. Catches more borderline attacks, but some ordinary prompts will be stopped too.',
  balanced: 'Recommended. The threshold the detector is evaluated at.',
  permissive: 'Blocks less. Fewer false alarms, but more borderline attacks get through.',
};

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function useOrg() {
  const [org, setOrg] = useState(null);
  const [error, setError] = useState('');
  const load = useCallback(() => {
    api.get('/api/org').then(setOrg).catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);
  return { org, setOrg, error, reload: load };
}

function Section({ title, description, children }) {
  return (
    <section className="card settings-section">
      <h2 className="settings-title">{title}</h2>
      {description && <p className="settings-desc">{description}</p>}
      {children}
    </section>
  );
}

function Status({ error, saved }) {
  if (error) return <div className="form-error" role="alert">{error}</div>;
  if (saved) return <div className="form-ok"><Check size={14} /> {saved}</div>;
  return null;
}

export function SettingsLayout() {
  return (
    <div className="tab-pane settings-layout">
      <aside className="settings-nav">
        <h1 className="settings-heading">Settings</h1>
        {SECTIONS.map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => `settings-link ${isActive ? 'active' : ''}`}>
            {label}
          </NavLink>
        ))}
      </aside>
      <div className="settings-body"><Outlet /></div>
    </div>
  );
}

export function OrganizationSettings() {
  const { can, refresh } = useAuth();
  const { org, setOrg, error: loadError } = useOrg();
  const [name, setName] = useState('');
  const [usage, setUsage] = useState(null);
  const [status, setStatus] = useState({});

  useEffect(() => { if (org) setName(org.name); }, [org]);
  useEffect(() => { api.get('/api/usage').then(setUsage).catch(() => {}); }, []);

  const save = async (changes, message) => {
    setStatus({});
    try {
      setOrg(await api.patch('/api/org', changes));
      setStatus({ saved: message });
      refresh();
    } catch (e) {
      setStatus({ error: e.message });
    }
  };

  if (loadError) return <Status error={loadError} />;
  if (!org) return <div className="spinner" />;
  const admin = can('admin');

  return (
    <>
      <Section title="Organisation" description="Everyone in your organisation shares its logs, review queue and API keys.">
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); save({ name }, 'Name saved.'); }}>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} disabled={!admin}
                 minLength={2} maxLength={120} aria-label="Organisation name" />
          {admin && <button className="btn btn-primary">Save</button>}
        </form>
        <Status {...status} />
      </Section>

      <Section title="Detection sensitivity"
               description="How confident the detector must be before a prompt is blocked. Signature rules for known attacks apply at every level.">
        <div className="radio-cards">
          {org.sensitivities.map((level) => (
            <label key={level} className={`radio-card ${org.sensitivity === level ? 'selected' : ''}`}>
              <input type="radio" name="sensitivity" value={level} disabled={!admin}
                     checked={org.sensitivity === level}
                     onChange={() => save({ sensitivity: level }, `Sensitivity set to ${level}.`)} />
              <strong>{level[0].toUpperCase() + level.slice(1)}</strong>
              <span>{SENSITIVITY_TEXT[level]}</span>
            </label>
          ))}
        </div>
        {!admin && <p className="muted small">Only admins can change this.</p>}
      </Section>

      <Section title="Usage" description="Resets daily at midnight UTC.">
        {usage ? (
          <div className="kpi-grid compact">
            <div className="kpi-card"><div className="kpi-title">Scans today</div>
              <div className="kpi-val">{usage.today.scans.toLocaleString()}</div></div>
            <div className="kpi-card"><div className="kpi-title">Assistant answers today</div>
              <div className="kpi-val">{usage.today.chat_messages} / {usage.limits.chat_daily_cap}</div></div>
            <div className="kpi-card"><div className="kpi-title">Rate limit</div>
              <div className="kpi-val">{usage.limits.rate_limit_per_minute}<span className="kpi-sub"> / min per key</span></div></div>
            <div className="kpi-card"><div className="kpi-title">Scans, last 30 days</div>
              <div className="kpi-val">{usage.history.reduce((n, d) => n + d.scans, 0).toLocaleString()}</div></div>
          </div>
        ) : <div className="spinner" />}
      </Section>
    </>
  );
}

export function MembersSettings() {
  const { can } = useAuth();
  const [data, setData] = useState(null);
  const [invite, setInvite] = useState({ email: '', role: 'member' });
  const [status, setStatus] = useState({});

  const load = useCallback(() => {
    api.get('/api/org/members').then(setData).catch((e) => setStatus({ error: e.message }));
  }, []);
  useEffect(load, [load]);

  const act = async (fn, message) => {
    setStatus({});
    try {
      await fn();
      setStatus({ saved: message });
      load();
    } catch (e) {
      setStatus({ error: e.message });
    }
  };

  if (!data) return <div className="spinner" />;
  const admin = can('admin');
  const owner = can('owner');

  return (
    <>
      <Section title="Members" description="Owners manage roles. Admins manage keys, invitations and settings. Members use the firewall and view results.">
        <table className="settings-table">
          <thead><tr><th>Email</th><th>Role</th><th>Last sign-in</th><th /></tr></thead>
          <tbody>
            {data.members.map((m) => (
              <tr key={m.id}>
                <td>{m.email}{m.is_you && <span className="tag">you</span>}</td>
                <td>
                  {owner && !m.is_you ? (
                    <select value={m.role} aria-label={`Role for ${m.email}`}
                            onChange={(e) => act(() => api.patch(`/api/org/members/${m.id}`, { role: e.target.value }),
                                                 `${m.email} is now ${e.target.value}.`)}>
                      <option value="member">member</option>
                      <option value="admin">admin</option>
                      <option value="owner">owner</option>
                    </select>
                  ) : m.role}
                </td>
                <td className="muted">{fmtDate(m.last_login_at)}</td>
                <td className="right">
                  {admin && !m.is_you && (
                    <button className="btn btn-sm btn-reject" title="Remove member"
                            onClick={() => confirm(`Remove ${m.email}? They are signed out immediately.`)
                              && act(() => api.del(`/api/org/members/${m.id}`), `${m.email} removed.`)}>
                      <Trash2 size={14} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <Status {...status} />
      </Section>

      {admin && (
        <Section title="Invite a teammate" description="They'll get an email link to set a password and join this organisation.">
          <form className="inline-form" onSubmit={(e) => {
            e.preventDefault();
            act(() => api.post('/api/org/invites', invite), `Invitation sent to ${invite.email}.`)
              .then(() => setInvite({ email: '', role: 'member' }));
          }}>
            <input type="email" placeholder="colleague@company.com" required value={invite.email}
                   onChange={(e) => setInvite({ ...invite, email: e.target.value })} aria-label="Email to invite" />
            <select value={invite.role} onChange={(e) => setInvite({ ...invite, role: e.target.value })} aria-label="Role">
              <option value="member">member</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn btn-primary"><UserPlus size={15} /> Invite</button>
          </form>
          {data.invites.length > 0 && (
            <table className="settings-table">
              <thead><tr><th>Pending invitation</th><th>Role</th><th>Expires</th><th /></tr></thead>
              <tbody>
                {data.invites.map((i) => (
                  <tr key={i.id}>
                    <td>{i.email}</td><td>{i.role}</td><td className="muted">{fmtDate(i.expires_at)}</td>
                    <td className="right">
                      <button className="btn btn-sm btn-secondary"
                              onClick={() => act(() => api.del(`/api/org/invites/${i.id}`), 'Invitation revoked.')}>
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      )}
    </>
  );
}

export function ApiKeysSettings() {
  const { can } = useAuth();
  const [keys, setKeys] = useState(null);
  const [name, setName] = useState('');
  const [created, setCreated] = useState(null);
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState({});

  const load = useCallback(() => {
    api.get('/api/keys').then((d) => setKeys(d.keys)).catch((e) => setStatus({ error: e.message }));
  }, []);
  useEffect(load, [load]);

  const create = async (e) => {
    e.preventDefault();
    setStatus({});
    try {
      setCreated(await api.post('/api/keys', { name }));
      setCopied(false);
      setName('');
      load();
    } catch (err) {
      setStatus({ error: err.message });
    }
  };

  const revoke = async (k) => {
    if (!confirm(`Revoke "${k.name}"? Anything using it stops working immediately.`)) return;
    try {
      await api.del(`/api/keys/${k.id}`);
      load();
    } catch (err) {
      setStatus({ error: err.message });
    }
  };

  const copy = async () => {
    await navigator.clipboard.writeText(created.key);
    setCopied(true);
  };

  const admin = can('admin');
  return (
    <>
      <Section title="API keys"
               description="Send a key in the X-API-Key header (or as a Bearer token with OpenAI SDKs). Keys act on behalf of the whole organisation.">
        {created && (
          <div className="key-reveal" role="status">
            <div className="key-reveal-head"><KeyRound size={16} /> Copy your new key now — it won't be shown again.</div>
            <div className="key-reveal-row">
              <code>{created.key}</code>
              <button className="btn btn-sm btn-primary" onClick={copy}>
                {copied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy</>}
              </button>
            </div>
          </div>
        )}
        {admin && (
          <form className="inline-form" onSubmit={create}>
            <input type="text" placeholder="Key name, e.g. production-backend" required maxLength={80}
                   value={name} onChange={(e) => setName(e.target.value)} aria-label="Key name" />
            <button className="btn btn-primary"><KeyRound size={15} /> Create key</button>
          </form>
        )}
        <Status {...status} />
        {!keys ? <div className="spinner" /> : keys.length === 0 ? (
          <p className="muted">No keys yet.{admin ? ' Create one to call the API from your application.' : ''}</p>
        ) : (
          <table className="settings-table">
            <thead><tr><th>Name</th><th>Key</th><th>Created</th><th>Last used</th><th /></tr></thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className={k.revoked ? 'revoked' : ''}>
                  <td>{k.name}</td>
                  <td><code>{k.prefix}…</code></td>
                  <td className="muted">{fmtDate(k.created_at)}</td>
                  <td className="muted">{fmtDate(k.last_used_at)}</td>
                  <td className="right">
                    {k.revoked ? <span className="tag">revoked</span> : admin && (
                      <button className="btn btn-sm btn-secondary" onClick={() => revoke(k)}>Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

export function IntegrationsSettings() {
  const { can } = useAuth();
  const { org, setOrg } = useOrg();
  const [form, setForm] = useState({ base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini', api_key: '' });
  const [status, setStatus] = useState({});
  const origin = window.location.origin;

  useEffect(() => {
    if (org?.upstream.configured) {
      setForm((f) => ({ ...f, base_url: org.upstream.base_url, model: org.upstream.model }));
    }
  }, [org]);

  const save = async (e) => {
    e.preventDefault();
    setStatus({});
    try {
      setOrg(await api.put('/api/org/upstream', form));
      setForm((f) => ({ ...f, api_key: '' }));
      setStatus({ saved: 'Upstream saved. Your key is stored encrypted and never shown again.' });
    } catch (err) {
      setStatus({ error: err.message });
    }
  };

  const remove = async () => {
    if (!confirm('Remove the upstream provider? The /v1 proxy will stop forwarding requests.')) return;
    try {
      setOrg(await api.del('/api/org/upstream'));
      setStatus({ saved: 'Upstream removed.' });
    } catch (err) {
      setStatus({ error: err.message });
    }
  };

  if (!org) return <div className="spinner" />;
  const admin = can('admin');

  return (
    <>
      <Section title="OpenAI-compatible proxy"
               description="Point any OpenAI SDK at RedTeamGPT. Each request is screened; safe ones are forwarded to your own provider with your key, and the reply is screened before it comes back.">
        <div className={`status-line ${org.upstream.configured ? 'ok' : ''}`}>
          {org.upstream.configured
            ? <>Forwarding to <code>{org.upstream.base_url}</code> using <code>{org.upstream.model}</code>.</>
            : 'No upstream configured yet — the proxy will screen requests but cannot answer them.'}
        </div>
        {admin ? (
          <form className="stack-form" onSubmit={save}>
            <label className="field"><span className="field-label">Provider base URL</span>
              <input type="url" required value={form.base_url}
                     onChange={(e) => setForm({ ...form, base_url: e.target.value })} />
              <span className="field-hint">Any OpenAI-compatible endpoint: OpenAI, Groq, Together, Azure OpenAI, a self-hosted gateway.</span>
            </label>
            <label className="field"><span className="field-label">Default model</span>
              <input type="text" required value={form.model}
                     onChange={(e) => setForm({ ...form, model: e.target.value })} />
            </label>
            <label className="field"><span className="field-label">Provider API key</span>
              <input type="password" required autoComplete="off" placeholder={org.upstream.configured ? 'Enter a new key to replace the stored one' : 'sk-…'}
                     value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} />
            </label>
            <div className="action-row">
              <button className="btn btn-primary">Save upstream</button>
              {org.upstream.configured && (
                <button type="button" className="btn btn-secondary" onClick={remove}>Remove</button>
              )}
            </div>
          </form>
        ) : <p className="muted small">Only admins can change the upstream provider.</p>}
        <Status {...status} />
      </Section>

      <Section title="Use it from your code">
        <pre className="code-block">{`from openai import OpenAI

client = OpenAI(
    base_url="${origin}/v1",
    api_key="rtg_live_…",   # a RedTeamGPT key from Settings → API keys
)

resp = client.chat.completions.create(
    messages=[{"role": "user", "content": "Summarise this ticket…"}],
    model="${org.upstream.model || 'gpt-4o-mini'}",
)
# Blocked prompts raise openai.BadRequestError with code "prompt_injection_detected".`}</pre>
        <p className="muted small">Streaming responses are not supported yet; send <code>stream=False</code>.</p>
      </Section>
    </>
  );
}

export function DataSettings() {
  const { can, me } = useAuth();
  const navigate = useNavigate();
  const { org, setOrg } = useOrg();
  const [retention, setRetention] = useState(30);
  const [confirmName, setConfirmName] = useState('');
  const [status, setStatus] = useState({});

  useEffect(() => { if (org) setRetention(org.retention_days); }, [org]);

  const save = async (changes, message) => {
    setStatus({});
    try {
      setOrg(await api.patch('/api/org', changes));
      setStatus({ saved: message });
    } catch (e) {
      setStatus({ error: e.message });
    }
  };

  const deleteOrg = async () => {
    if (!confirm('This permanently deletes the organisation, every member, key, log and review. Continue?')) return;
    try {
      await api.del('/api/org', { confirm_name: confirmName });
      navigate('/', { replace: true });
      window.location.reload();
    } catch (e) {
      setStatus({ error: e.message });
    }
  };

  if (!org) return <div className="spinner" />;
  const admin = can('admin');

  return (
    <>
      <Section title="Retention" description="Audit logs older than this are deleted automatically.">
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); save({ retention_days: Number(retention) }, `Logs are kept for ${retention} days.`); }}>
          <input type="number" min={1} max={org.max_retention_days} value={retention} disabled={!admin}
                 onChange={(e) => setRetention(e.target.value)} aria-label="Retention in days" />
          <span className="muted">days (max {org.max_retention_days})</span>
          {admin && <button className="btn btn-primary">Save</button>}
        </form>
      </Section>

      <Section title="Prompt storage">
        <label className="toggle-row">
          <input type="checkbox" checked={org.store_prompts} disabled={!admin}
                 onChange={(e) => save({ store_prompts: e.target.checked },
                   e.target.checked ? 'Prompt text will be stored.' : 'Prompt text will no longer be stored.')} />
          <span>
            <strong>Store the text of scanned prompts</strong>
            <span className="muted block">When off, logs keep the verdict, category and matched phrases but not the prompt itself, and borderline prompts are not queued for review.</span>
          </span>
        </label>
      </Section>

      <Section title="Help improve detection">
        <label className="toggle-row">
          <input type="checkbox" checked={org.contribute_training} disabled={!admin}
                 onChange={(e) => save({ contribute_training: e.target.checked },
                   e.target.checked ? 'Thank you — reviewed decisions may be used for training.' : 'Opted out of training.')} />
          <span>
            <strong>Allow reviewed decisions to be used to train the detector</strong>
            <span className="muted block">Off by default. Only prompts your team has reviewed in the Review tab are shared — never ordinary traffic.</span>
          </span>
        </label>
      </Section>

      <Section title="Export">
        <a className="btn btn-secondary" href="/api/logs/export">Download audit log (JSON)</a>
      </Section>
      <Status {...status} />

      {me?.user.role === 'owner' && (
        <Section title="Delete organisation">
          <div className="danger-zone">
            <AlertTriangle size={18} />
            <div>
              <p>Permanently deletes <strong>{org.name}</strong> with all members, API keys, logs and reviews. This cannot be undone.</p>
              <div className="inline-form">
                <input type="text" placeholder={`Type "${org.name}" to confirm`} value={confirmName}
                       onChange={(e) => setConfirmName(e.target.value)} aria-label="Confirm organisation name" />
                <button className="btn btn-reject" disabled={confirmName !== org.name} onClick={deleteOrg}>
                  Delete organisation
                </button>
              </div>
            </div>
          </div>
        </Section>
      )}
    </>
  );
}

export function AccountSettings() {
  const { me } = useAuth();
  const [form, setForm] = useState({ current_password: '', new_password: '' });
  const [status, setStatus] = useState({});

  const submit = async (e) => {
    e.preventDefault();
    setStatus({});
    try {
      await api.post('/api/auth/change-password', form);
      setForm({ current_password: '', new_password: '' });
      setStatus({ saved: 'Password changed. Other devices have been signed out.' });
    } catch (err) {
      setStatus({ error: err.message });
    }
  };

  return (
    <>
      <Section title="Your account">
        <div className="meta-info-grid">
          <div className="meta-item"><span className="meta-label">Email</span><span className="meta-val">{me.user.email}</span></div>
          <div className="meta-item"><span className="meta-label">Role</span><span className="meta-val">{me.user.role}</span></div>
          <div className="meta-item"><span className="meta-label">Organisation</span><span className="meta-val">{me.org.name}</span></div>
        </div>
      </Section>
      <Section title="Change password">
        <form className="stack-form" onSubmit={submit}>
          <label className="field"><span className="field-label">Current password</span>
            <input type="password" autoComplete="current-password" required value={form.current_password}
                   onChange={(e) => setForm({ ...form, current_password: e.target.value })} />
          </label>
          <label className="field"><span className="field-label">New password</span>
            <input type="password" autoComplete="new-password" required minLength={10} value={form.new_password}
                   onChange={(e) => setForm({ ...form, new_password: e.target.value })} />
            <span className="field-hint">At least 10 characters.</span>
          </label>
          <div className="action-row"><button className="btn btn-primary">Change password</button></div>
        </form>
        <Status {...status} />
      </Section>
    </>
  );
}
