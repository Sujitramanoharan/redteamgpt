import React, { useEffect, useRef, useState } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import { Shield, MailCheck } from 'lucide-react';
import { api } from '../api';
import { useAuth, FullPageLoader } from '../auth';

function AuthCard({ title, subtitle, children, footer }) {
  return (
    <div className="auth-shell">
      <div className="auth-card">
        <Link to="/" className="auth-brand">
          <span className="logo-shield"><Shield size={20} /></span>
          <span className="logo-title">RedTeam<span className="highlight">GPT</span></span>
        </Link>
        <h1 className="auth-title">{title}</h1>
        {subtitle && <p className="auth-subtitle">{subtitle}</p>}
        {children}
        {footer && <div className="auth-footer">{footer}</div>}
      </div>
    </div>
  );
}

function Field({ label, hint, ...props }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input {...props} />
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

function ErrorNote({ message }) {
  if (!message) return null;
  return <div className="form-error" role="alert">{message}</div>;
}

// Where to go after signing in: back to the page that sent us here, but only
// ever within the app, so ?next= cannot be used to bounce users off-site.
function nextPath(params) {
  const next = params.get('next') || '';
  return next.startsWith('/app') ? next : '/app';
}

export function Login() {
  const { me, setMe } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [form, setForm] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [unverified, setUnverified] = useState(false);
  const [busy, setBusy] = useState(false);

  if (me) return <Navigate to={nextPath(params)} replace />;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    setUnverified(false);
    try {
      setMe(await api.post('/api/auth/login', form));
      navigate(nextPath(params), { replace: true });
    } catch (err) {
      if (err.message === 'verify_email') setUnverified(true);
      else setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    await api.post('/api/auth/resend-verification', { email: form.email });
    setUnverified(false);
    setError('');
    alert('If that address has an unverified account, a new link is on its way.');
  };

  return (
    <AuthCard
      title="Sign in"
      subtitle="Welcome back to your firewall dashboard."
      footer={<>New here? <Link to="/signup">Create an account</Link></>}
    >
      <form onSubmit={submit} className="auth-form">
        <Field label="Email" type="email" autoComplete="email" required autoFocus
               value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <Field label="Password" type="password" autoComplete="current-password" required
               value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <ErrorNote message={error} />
        {unverified && (
          <div className="form-error" role="alert">
            Confirm your email address first — check your inbox for the link.{' '}
            <button type="button" className="link-btn" onClick={resend}>Send a new link</button>
          </div>
        )}
        <button className="btn btn-primary btn-block" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <Link to="/forgot-password" className="auth-link">Forgot your password?</Link>
      </form>
    </AuthCard>
  );
}

export function Signup() {
  const { me, setMe } = useAuth();
  const navigate = useNavigate();
  const [config, setConfig] = useState(null);
  const [form, setForm] = useState({ name: '', email: '', org_name: '', password: '' });
  const [error, setError] = useState('');
  const [sentTo, setSentTo] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get('/api/auth/config').then(setConfig).catch(() => setConfig({ signup_enabled: true }));
  }, []);

  if (me) return <Navigate to="/app" replace />;
  if (!config) return <FullPageLoader />;
  if (!config.signup_enabled) {
    return <AuthCard title="Sign-up is closed" subtitle="New accounts are not being accepted right now."
                     footer={<Link to="/login">Back to sign in</Link>} />;
  }

  if (sentTo) {
    return (
      <AuthCard title="Check your email" footer={<Link to="/login">Back to sign in</Link>}>
        <div className="auth-notice">
          <MailCheck size={28} />
          <p>We sent a confirmation link to <strong>{sentTo}</strong>. Open it to finish creating
            your account. The link expires in 24 hours.</p>
        </div>
      </AuthCard>
    );
  }

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const res = await api.post('/api/auth/signup', form);
      if (res.verification_required) setSentTo(form.email);
      else {
        setMe(res);
        navigate('/app', { replace: true });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const minLen = config.min_password_length || 10;
  return (
    <AuthCard
      title="Create your account"
      subtitle="Free. Protect your AI apps from prompt injection in minutes."
      footer={<>Already have an account? <Link to="/login">Sign in</Link></>}
    >
      <form onSubmit={submit} className="auth-form">
        <Field label="Your name" autoComplete="name" type="text"
               value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <Field label="Work email" type="email" autoComplete="email" required
               value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <Field label="Organisation name" type="text" autoComplete="organization" required minLength={2}
               hint="Your team's workspace. You can invite colleagues later."
               value={form.org_name} onChange={(e) => setForm({ ...form, org_name: e.target.value })} />
        <Field label="Password" type="password" autoComplete="new-password" required minLength={minLen}
               hint={`At least ${minLen} characters.`}
               value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <ErrorNote message={error} />
        <button className="btn btn-primary btn-block" disabled={busy}>
          {busy ? 'Creating account…' : 'Create account'}
        </button>
      </form>
    </AuthCard>
  );
}

export function VerifyEmail() {
  const { setMe } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [error, setError] = useState('');
  const started = useRef(false);

  useEffect(() => {
    // StrictMode runs effects twice in development; the token is single-use.
    if (started.current) return;
    started.current = true;
    api.post('/api/auth/verify-email', { token: params.get('token') || '' })
      .then((me) => {
        setMe(me);
        navigate('/app', { replace: true });
      })
      .catch((err) => setError(err.message));
  }, [params, navigate, setMe]);

  if (!error) return <FullPageLoader />;
  return (
    <AuthCard title="Link not valid" subtitle={error}
              footer={<Link to="/login">Back to sign in</Link>} />
  );
}

export function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api.post('/api/auth/forgot-password', { email });
      setSent(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard title="Reset your password"
              subtitle={sent ? null : "Enter your email and we'll send you a reset link."}
              footer={<Link to="/login">Back to sign in</Link>}>
      {sent ? (
        <div className="auth-notice">
          <MailCheck size={28} />
          <p>If <strong>{email}</strong> has an account, a reset link is on its way. It expires in one hour.</p>
        </div>
      ) : (
        <form onSubmit={submit} className="auth-form">
          <Field label="Email" type="email" autoComplete="email" required autoFocus
                 value={email} onChange={(e) => setEmail(e.target.value)} />
          <ErrorNote message={error} />
          <button className="btn btn-primary btn-block" disabled={busy}>
            {busy ? 'Sending…' : 'Send reset link'}
          </button>
        </form>
      )}
    </AuthCard>
  );
}

function SetPasswordForm({ endpoint, title, subtitle, withName }) {
  const { setMe } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const body = { token: params.get('token') || '', password };
      if (withName) body.name = name;
      setMe(await api.post(endpoint, body));
      navigate('/app', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard title={title} subtitle={subtitle} footer={<Link to="/login">Back to sign in</Link>}>
      <form onSubmit={submit} className="auth-form">
        {withName && (
          <Field label="Your name" type="text" autoComplete="name"
                 value={name} onChange={(e) => setName(e.target.value)} />
        )}
        <Field label="New password" type="password" autoComplete="new-password" required minLength={10}
               hint="At least 10 characters." autoFocus
               value={password} onChange={(e) => setPassword(e.target.value)} />
        <ErrorNote message={error} />
        <button className="btn btn-primary btn-block" disabled={busy}>
          {busy ? 'Saving…' : 'Continue'}
        </button>
      </form>
    </AuthCard>
  );
}

export function ResetPassword() {
  return <SetPasswordForm endpoint="/api/auth/reset-password" title="Choose a new password"
                          subtitle="You'll be signed out everywhere else." />;
}

export function AcceptInvite() {
  return <SetPasswordForm endpoint="/api/auth/accept-invite" title="Join your team"
                          subtitle="Set a password to accept the invitation." withName />;
}
