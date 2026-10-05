import React, { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Shield, ShieldAlert, Cpu, Terminal, Layers, MessageSquare, FileSearch,
  ClipboardCheck, Settings, LogOut, ChevronDown,
} from 'lucide-react';
import { useAuth } from '../auth';

const TABS = [
  { to: 'assistant', icon: MessageSquare, label: 'Assistant' },
  { to: 'inspector', icon: Shield, label: 'Live Inspector' },
  { to: 'documents', icon: FileSearch, label: 'Document Scan' },
  { to: 'review', icon: ClipboardCheck, label: 'Review' },
  { to: 'adversarial', icon: ShieldAlert, label: 'Adversarial Lab' },
  { to: 'audit', icon: Layers, label: 'Security Audit' },
  { to: 'api', icon: Terminal, label: 'API Hub' },
  { to: 'model', icon: Cpu, label: 'Model' },
];

function UserMenu() {
  const { me, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);

  const signOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="user-menu" ref={ref}>
      <button className="user-menu-btn" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="user-menu-org">{me.org.name}</span>
        <span className="user-menu-email">{me.user.email}</span>
        <ChevronDown size={14} />
      </button>
      {open && (
        <div className="user-menu-pop" role="menu">
          <div className="user-menu-meta">Signed in as <strong>{me.user.role}</strong></div>
          <NavLink to="/app/settings" onClick={() => setOpen(false)} role="menuitem">
            <Settings size={14} /> Settings
          </NavLink>
          <button onClick={signOut} role="menuitem"><LogOut size={14} /> Sign out</button>
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const { me } = useAuth();
  const scans = me?.usage_today?.scans ?? 0;

  return (
    <div className="app-wrapper">
      <header className="top-nav">
        <NavLink to="/app" className="brand">
          <div className="logo-shield"><Shield size={24} /></div>
          <div className="brand-text">
            <span className="logo-title">RedTeam<span className="highlight">GPT</span></span>
            <span className="logo-subtitle">AI FIREWALL</span>
          </div>
        </NavLink>

        <nav className="nav-tabs">
          {TABS.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to} className={({ isActive }) => `nav-tab ${isActive ? 'active' : ''}`}>
              <Icon size={15} /> {label}
            </NavLink>
          ))}
        </nav>

        <div className="nav-right">
          <span className="usage-pill" title="Prompts scanned today by your organisation">
            {scans.toLocaleString()} scans today
          </span>
          <UserMenu />
        </div>
      </header>

      <main className="main-content">
        <Outlet />
      </main>

      <footer className="app-footer">
        <span>RedTeamGPT &copy; {new Date().getFullYear()}</span>
        <div className="footer-links">
          <NavLink to="/app/settings/api-keys">API keys</NavLink>
          <a href="/ready" target="_blank" rel="noreferrer">Service status</a>
        </div>
      </footer>
    </div>
  );
}
