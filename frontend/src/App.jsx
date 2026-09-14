import React, { useState } from 'react';
import { Shield, ShieldAlert, Cpu, Terminal, Layers } from 'lucide-react';
import InspectorTab from './components/InspectorTab';
import EvasionTab from './components/EvasionTab';
import TelemetryTab from './components/TelemetryTab';
import ApiHubTab from './components/ApiHubTab';
import ModelSpecsTab from './components/ModelSpecsTab';

export default function App() {
  const [activeTab, setActiveTab] = useState('inspector');

  return (
    <div className="app-wrapper">
      {/* Top Header Navigation */}
      <header className="top-nav">
        <div className="brand">
          <div className="logo-shield">
            <Shield size={24} />
          </div>
          <div className="brand-text">
            <span className="logo-title">
              RedTeam<span className="highlight">GPT</span>
            </span>
            <span className="logo-subtitle">REACT ENTERPRISE GUARDRAIL 2.0</span>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={`nav-tab ${activeTab === 'inspector' ? 'active' : ''}`}
            onClick={() => setActiveTab('inspector')}
          >
            <Shield size={15} /> Live Inspector
          </button>
          <button
            className={`nav-tab ${activeTab === 'evasion' ? 'active' : ''}`}
            onClick={() => setActiveTab('evasion')}
          >
            <ShieldAlert size={15} /> Adversarial Lab
          </button>
          <button
            className={`nav-tab ${activeTab === 'telemetry' ? 'active' : ''}`}
            onClick={() => setActiveTab('telemetry')}
          >
            <Layers size={15} /> Security Audit
          </button>
          <button
            className={`nav-tab ${activeTab === 'apiHub' ? 'active' : ''}`}
            onClick={() => setActiveTab('apiHub')}
          >
            <Terminal size={15} /> API Hub
          </button>
          <button
            className={`nav-tab ${activeTab === 'modelSpecs' ? 'active' : ''}`}
            onClick={() => setActiveTab('modelSpecs')}
          >
            <Cpu size={15} /> Model Specs
          </button>
        </nav>

        <div className="status-indicator-badge">
          <span className="status-dot pulsing" />
          <span className="status-text">FIREWALL ACTIVE</span>
        </div>
      </header>

      {/* Main Content Pane */}
      <main className="main-content">
        {activeTab === 'inspector' && <InspectorTab />}
        {activeTab === 'evasion' && <EvasionTab />}
        {activeTab === 'telemetry' && <TelemetryTab />}
        {activeTab === 'apiHub' && <ApiHubTab />}
        {activeTab === 'modelSpecs' && <ModelSpecsTab />}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <span>RedTeamGPT Security Intelligence Platform &copy; 2026. Powered by React, Vite, &amp; Transformers.</span>
        <div className="footer-links">
          <a href="/health" target="_blank" rel="noreferrer">Health Check API</a>
        </div>
      </footer>
    </div>
  );
}
