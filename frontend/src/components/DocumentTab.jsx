import React, { useRef, useState } from 'react';
import { FileUp, FileText, ShieldCheck, ShieldAlert, Loader2 } from 'lucide-react';
import { api } from '../api';

const ACCEPT = '.pdf,.docx,.txt,.md,.csv';

export default function DocumentTab() {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [dragging, setDragging] = useState(false);
  const [name, setName] = useState('');
  const inputRef = useRef(null);

  const upload = async (file) => {
    if (!file) return;
    setBusy(true);
    setError('');
    setResult(null);
    setName(file.name);

    const body = new FormData();
    body.append('file', file);

    try {
      setResult(await api.upload('/api/scan-document', body));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    upload(e.dataTransfer.files?.[0]);
  };

  const blocked = result?.malicious;

  return (
    <div className="tab-pane">
      <div className="pane-header">
        <div>
          <h2>Document Injection Scanner</h2>
          <p className="pane-desc">
            Attackers hide instructions inside files a person is likely to upload — a CV,
            an invoice, a report. The reader sees an ordinary document; an AI system
            reading it sees a command. This finds those passages.
          </p>
        </div>
      </div>

      <div
        className={`upload-zone ${dragging ? 'dragging' : ''} ${busy ? 'busy' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !busy && inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPT}
          hidden
          onChange={(e) => upload(e.target.files?.[0])}
        />
        <div className="upload-icon">
          {busy ? <Loader2 size={28} className="spin" /> : <FileUp size={28} />}
        </div>
        <h3>{busy ? `Scanning ${name}…` : 'Drop a document here, or click to choose'}</h3>
        <p>PDF, Word, text, Markdown or CSV · up to 5 MB</p>
      </div>

      {error && (
        <div className="card" style={{ borderLeft: '3px solid var(--color-danger)', marginTop: 18 }}>
          <strong style={{ color: 'var(--color-danger)' }}>Could not scan</strong>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 5 }}>{error}</p>
        </div>
      )}

      {result && (
        <div className="doc-results">
          <div className={`verdict-banner ${blocked ? 'blocked' : 'allowed'}`}>
            <div className="verdict-icon">
              {blocked ? <ShieldAlert size={26} /> : <ShieldCheck size={26} />}
            </div>
            <div className="verdict-text-group">
              <span className="verdict-label">{result.verdict}</span>
              <span className="verdict-action">
                <FileText size={12} style={{ verticalAlign: '-2px', marginRight: 4 }} />
                {result.filename}
              </span>
            </div>
            <div className="verdict-badges">
              {result.priority && (
                <div className="verdict-priority-badge" style={{ backgroundColor: result.priority.color }}>
                  {result.priority.level} · {result.priority.label}
                </div>
              )}
              <div className="verdict-risk-badge">{result.risk_score}/100</div>
            </div>
          </div>

          <div className="meta-info-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginTop: 14 }}>
            <div className="meta-item">
              <span className="meta-label">Characters</span>
              <span className="meta-val">{result.stats.characters.toLocaleString()}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Passages scanned</span>
              <span className="meta-val">{result.stats.passages_scanned}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Suspicious</span>
              <span className={`meta-val ${blocked ? 'text-danger' : ''}`}>
                {result.stats.suspicious_passages}
              </span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Category</span>
              <span className="meta-val highlight">{result.category}</span>
            </div>
          </div>

          <div className={`explain-card ${blocked ? 'blocked' : 'allowed'}`} style={{ marginTop: 14 }}>
            <div className="explain-headline">
              {blocked ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}
              <span>{result.summary}</span>
            </div>
          </div>

          {result.findings?.length > 0 && (
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {result.findings.map((f, i) => (
                <div key={i} className="doc-finding">
                  <div className="doc-finding-head">
                    <span className="doc-finding-title">
                      Passage {f.passage_index + 1} — {f.category}
                    </span>
                    <span
                      className="verdict-priority-badge"
                      style={{ backgroundColor: f.priority?.color }}
                    >
                      {f.priority?.level} · risk {f.risk_score}
                    </span>
                  </div>

                  <div className="doc-quote">
                    <span className="doc-quote-label">
                      {f.pinpointed ? 'Injected instruction found' : 'Suspicious passage'}
                    </span>
                    <pre>{f.offending_text}</pre>
                  </div>

                  <p className="doc-finding-why">{f.explanation?.what_it_means}</p>

                  {f.explanation?.evidence?.length > 0 && (
                    <div className="chat-phrases" style={{ marginTop: 8 }}>
                      {f.explanation.evidence.map((ev, k) => (
                        <code key={k} title={ev.reason}>{ev.phrase}</code>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
