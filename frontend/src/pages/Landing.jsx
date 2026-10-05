import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, ShieldCheck, FileSearch, Terminal, Eye, Lock } from 'lucide-react';
import { useAuth } from '../auth';

const FEATURES = [
  { icon: ShieldCheck, title: 'Blocks prompt injection',
    text: 'A trained detector plus signature rules catch jailbreaks, system-prompt extraction and encoded payloads before they reach your model.' },
  { icon: Eye, title: 'Explains every verdict',
    text: 'Each block says what the prompt was trying to do, why it is dangerous and what triggered it, in plain language.' },
  { icon: Terminal, title: 'Drop-in for OpenAI SDKs',
    text: 'Point your existing OpenAI client at RedTeamGPT. Safe requests go to your own provider; attacks never leave.' },
  { icon: FileSearch, title: 'Scans documents',
    text: 'Find instructions hidden inside PDFs and Word files before an AI assistant reads them.' },
  { icon: Lock, title: 'Your data stays yours',
    text: 'Each organisation is isolated. Choose your retention period, or stop storing prompt text entirely.' },
  { icon: Shield, title: 'Human review loop',
    text: 'Borderline decisions are queued for your team to confirm, so you can see exactly where the firewall is unsure.' },
];

export default function Landing() {
  const { me } = useAuth();
  return (
    <div className="landing">
      <header className="landing-nav">
        <div className="brand">
          <div className="logo-shield"><Shield size={22} /></div>
          <span className="logo-title">RedTeam<span className="highlight">GPT</span></span>
        </div>
        <nav className="landing-actions">
          {me ? (
            <Link className="btn btn-primary" to="/app">Open dashboard</Link>
          ) : (
            <>
              <Link className="btn btn-secondary" to="/login">Sign in</Link>
              <Link className="btn btn-primary" to="/signup">Get started free</Link>
            </>
          )}
        </nav>
      </header>

      <section className="landing-hero">
        <h1>A firewall for the prompts your AI reads</h1>
        <p>
          RedTeamGPT screens every message sent to your language model and stops jailbreaks,
          prompt injection and data-leak attempts — with an explanation your team can act on.
        </p>
        <div className="landing-cta">
          <Link className="btn btn-primary" to={me ? '/app' : '/signup'}>
            {me ? 'Go to your dashboard' : 'Create a free account'}
          </Link>
          <a className="btn btn-secondary" href="#features">How it works</a>
        </div>
        <pre className="landing-code">{`curl -X POST https://<your-deployment>/api/check \\
  -H "X-API-Key: rtg_live_…" \\
  -d '{"prompt": "Ignore all previous instructions…"}'

→ {"verdict": "BLOCKED", "risk_score": 100,
   "category": "System Prompt Extraction", ...}`}</pre>
      </section>

      <section id="features" className="landing-features">
        {FEATURES.map(({ icon: Icon, title, text }) => (
          <div key={title} className="card landing-feature">
            <Icon size={22} className="landing-feature-icon" />
            <h3>{title}</h3>
            <p>{text}</p>
          </div>
        ))}
      </section>

      <section className="landing-honest card">
        <h3>What it can and can't do</h3>
        <p>
          No detector catches every attack. RedTeamGPT is a strong layer, not a guarantee: keep
          least-privilege tool access and output checks in your application too. Our detection
          accuracy is measured on held-out, real-world prompts and published in the dashboard.
        </p>
      </section>

      <footer className="app-footer">
        <span>RedTeamGPT &copy; {new Date().getFullYear()}</span>
        <div className="footer-links">
          <Link to="/login">Sign in</Link>
          <Link to="/signup">Sign up</Link>
        </div>
      </footer>
    </div>
  );
}
