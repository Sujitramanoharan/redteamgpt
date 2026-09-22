import React, { useState, useEffect } from 'react';
import { Download, Trash2, Search, BarChart2, ShieldAlert } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';

export default function TelemetryTab() {
  const [metrics, setMetrics] = useState(null);
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("ALL");

  useEffect(() => {
    fetchTelemetry();
  }, [verdictFilter, search]);

  const fetchTelemetry = async () => {
    try {
      const [mRes, lRes] = await Promise.all([
        fetch("/api/metrics"),
        fetch(`/api/logs?limit=50&verdict=${verdictFilter === 'ALL' ? '' : verdictFilter}&search=${encodeURIComponent(search)}`)
      ]);

      if (mRes.ok) setMetrics(await mRes.json());
      if (lRes.ok) {
        const lData = await lRes.json();
        setLogs(lData.logs || []);
      }
    } catch (err) {
      console.error("Failed to fetch telemetry:", err);
    }
  };

  const clearHistory = async () => {
    if (!confirm("Are you sure you want to clear all security logs?")) return;
    await fetch("/api/logs/clear", { method: "POST" });
    fetchTelemetry();
  };

  const exportLogs = () => {
    window.open("/api/logs/export", "_blank");
  };

  const t = metrics?.telemetry || {};
  const pieData = [
    { name: 'Blocked', value: t.total_blocked || 0, color: '#ef4444' },
    { name: 'Allowed', value: t.total_allowed || 0, color: '#10b981' },
  ];

  const categoryData = Object.entries(t.category_distribution || {}).map(([name, count]) => ({
    name: name.length > 18 ? name.substring(0, 18) + '...' : name,
    count
  }));

  return (
    <div className="tab-pane">
      <div className="pane-header">
        <div>
          <h2>Security Audit & Telemetry Dashboard</h2>
          <p className="pane-desc">Real-time aggregate security statistics and searchable inspection audit trail.</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-secondary btn-sm" onClick={exportLogs}>
            <Download size={14} /> Export JSON
          </button>
          <button className="btn btn-secondary btn-sm" onClick={clearHistory}>
            <Trash2 size={14} /> Clear History
          </button>
        </div>
      </div>

      {/* KPI Grid */}
      <div className="kpi-grid">
        <div className="kpi-card card">
          <span className="kpi-title">Total Prompts Scanned</span>
          <div className="kpi-val">{t.total_scanned || 0}</div>
          <span className="kpi-sub">Real-time session total</span>
        </div>
        <div className="kpi-card card">
          <span className="kpi-title">Block Rate %</span>
          <div className="kpi-val text-danger">{t.block_rate_percent || 0}%</div>
          <span className="kpi-sub">Threats intercepted</span>
        </div>
        <div className="kpi-card card">
          <span className="kpi-title">Avg Latency</span>
          <div className="kpi-val text-cyan">{t.avg_latency_ms || 0} ms</div>
          <span className="kpi-sub">Sub-millisecond inference</span>
        </div>
        <div className="kpi-card card">
          <span className="kpi-title">Average Risk Score</span>
          <div className="kpi-val text-warning">{t.avg_risk_score || 0} / 100</div>
          <span className="kpi-sub">Across all queries</span>
        </div>
      </div>

      {/* Recharts Analytics Charts */}
      {t.total_scanned > 0 && (
        <div className="charts-row">
          <div className="card" style={{ height: 260 }}>
            <span className="card-title" style={{ fontSize: 13, marginBottom: 12 }}>Threat vs Safe Ratio</span>
            <ResponsiveContainer width="100%" height="80%">
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label>
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: 'rgba(255,255,255,0.1)' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="card" style={{ height: 260 }}>
            <span className="card-title" style={{ fontSize: 13, marginBottom: 12 }}>Threat Category Distribution</span>
            <ResponsiveContainer width="100%" height="80%">
              <BarChart data={categoryData}>
                <XAxis dataKey="name" stroke="#9ca3af" fontSize={10} />
                <YAxis stroke="#9ca3af" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: 'rgba(255,255,255,0.1)' }} />
                <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Audit Data Table */}
      <div className="card audit-table-card">
        <div className="table-controls">
          <div className="search-box">
            <input
              type="text"
              placeholder="Search prompts or categories..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="filter-group">
            <button className={`filter-btn ${verdictFilter === 'ALL' ? 'active' : ''}`} onClick={() => setVerdictFilter('ALL')}>All</button>
            <button className={`filter-btn ${verdictFilter === 'BLOCKED' ? 'active' : ''}`} onClick={() => setVerdictFilter('BLOCKED')}>Blocked</button>
            <button className={`filter-btn ${verdictFilter === 'ALLOWED' ? 'active' : ''}`} onClick={() => setVerdictFilter('ALLOWED')}>Allowed</button>
          </div>
        </div>

        <div className="table-responsive">
          <table className="audit-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Verdict</th>
                <th>Risk Score</th>
                <th>Category</th>
                <th>Prompt Snippet</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center muted py-4">No security audit logs recorded. Run prompt scans to populate.</td>
                </tr>
              ) : (
                logs.map((l) => {
                  const isBlocked = l.verdict === 'BLOCKED';
                  const dateStr = l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '--';
                  const snippet = l.prompt ? (l.prompt.length > 55 ? l.prompt.substring(0, 55) + '...' : l.prompt) : '--';
                  return (
                    <tr key={l.id ?? `${l.timestamp}-${l.risk_score}`}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{l.id}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{dateStr}</td>
                      <td>
                        <span className={`badge ${isBlocked ? 'badge-blocked' : 'badge-allowed'}`}>
                          {l.verdict}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold' }}>{l.risk_score}</td>
                      <td style={{ fontSize: 12, color: 'var(--color-cyan)' }}>{l.category}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={l.prompt}>
                        {snippet}
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{l.latency_ms} ms</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
