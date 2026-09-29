import React, { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, XCircle, ClipboardCheck, RefreshCw, Inbox } from 'lucide-react';
import { api } from '../api';

export default function ReviewTab() {
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [tab, setTab] = useState('pending');
  const [busy, setBusy] = useState(false);
  const [notes, setNotes] = useState({});
  const [message, setMessage] = useState('');

  const load = useCallback(async () => {
    setBusy(true);
    try {
      const [q, s] = await Promise.all([
        api.get(`/api/review/queue?status=${tab}`),
        api.get('/api/review/stats'),
      ]);
      setItems(q.items || []);
      setStats(s);
    } catch {
      setMessage('Could not load the review queue.');
    } finally {
      setBusy(false);
    }
  }, [tab]);

  useEffect(() => { load(); }, [load]);

  const decide = async (id, trueLabel) => {
    try {
      await api.post(`/api/review/${id}`, { true_label: trueLabel, note: notes[id] || '' });
    } catch (err) {
      setMessage(err.message);
    }
    load();
  };


  return (
    <div className="tab-pane">
      <div className="pane-header">
        <div>
          <h2>Human Review Queue</h2>
          <p className="pane-desc">
            When the rule layer and the classifier disagree, a person decides. Those
            decisions show exactly where the firewall is unsure. Admins record decisions;
            if your organisation opts in under Settings → Data &amp; privacy, they also help
            train the detector.
          </p>
        </div>
        <div className="quick-stats-pills">
          <button className="btn btn-secondary btn-sm" onClick={load} disabled={busy}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {stats && (
        <div className="meta-info-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 16 }}>
          <div className="meta-item">
            <span className="meta-label">Pending</span>
            <span className="meta-val highlight">{stats.pending}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Reviewed</span>
            <span className="meta-val">{stats.reviewed}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Agreement</span>
            <span className="meta-val">
              {stats.agreement_rate == null ? '--' : `${(stats.agreement_rate * 100).toFixed(0)}%`}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-label">False positives</span>
            <span className="meta-val text-danger">{stats.false_positives}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">False negatives</span>
            <span className="meta-val text-danger">{stats.false_negatives}</span>
          </div>
        </div>
      )}

      {message && (
        <div className="chat-notice" style={{ marginBottom: 16, textAlign: 'left' }}>{message}</div>
      )}

      <div className="sub-tabs" style={{ marginBottom: 14 }}>
        <button className={`sub-tab ${tab === 'pending' ? 'active' : ''}`}
                onClick={() => setTab('pending')}>Awaiting review</button>
        <button className={`sub-tab ${tab === 'reviewed' ? 'active' : ''}`}
                onClick={() => setTab('reviewed')}>Decided</button>
      </div>

      {items.length === 0 ? (
        <div className="card empty-state">
          <div className="empty-icon"><Inbox size={30} /></div>
          <h3>{tab === 'pending' ? 'Nothing waiting' : 'Nothing decided yet'}</h3>
          <p>
            {tab === 'pending'
              ? 'Items appear here when the two detection layers disagree, or when someone disputes a verdict.'
              : 'Decisions you make will be listed here and exported as training data.'}
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {items.map(item => (
            <div key={item.id} className="review-item">
              <div className="review-head">
                <span className={`badge ${item.predicted_label ? 'badge-blocked' : 'badge-allowed'}`}>
                  Firewall said {item.verdict}
                </span>
                <span className="review-meta">risk {item.risk_score}/100 · {item.category}</span>
                <span className="review-reason">{item.reason_text}</span>
              </div>

              <pre className="review-prompt">{item.prompt}</pre>

              {tab === 'pending' ? (
                <>
                  <input
                    className="review-note"
                    placeholder="Optional note for the record…"
                    value={notes[item.id] || ''}
                    onChange={e => setNotes(n => ({ ...n, [item.id]: e.target.value }))}
                  />
                  <div className="review-actions">
                    <span className="review-question">Was the firewall right?</span>
                    <button className="btn btn-confirm"
                            onClick={() => decide(item.id, item.predicted_label)}>
                      <CheckCircle2 size={14} /> Correct
                    </button>
                    <button className="btn btn-reject"
                            onClick={() => decide(item.id, item.predicted_label ? 0 : 1)}>
                      <XCircle size={14} /> Wrong — should be{' '}
                      {item.predicted_label ? 'ALLOWED' : 'BLOCKED'}
                    </button>
                  </div>
                </>
              ) : (
                <div className="review-outcome">
                  <ClipboardCheck size={14} />
                  <span>
                    Reviewer marked this <strong>{item.true_label ? 'malicious' : 'benign'}</strong>
                    {' — firewall was '}
                    <strong className={item.true_label === item.predicted_label ? 'text-success' : 'text-danger'}>
                      {item.true_label === item.predicted_label ? 'correct' : 'wrong'}
                    </strong>
                  </span>
                  {item.reviewer_note && <em>“{item.reviewer_note}”</em>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
