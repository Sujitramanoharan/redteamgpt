import React, { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';

const pct = (v) => (v == null ? '--' : `${(v * 100).toFixed(1)}%`);
const num = (v) => (v == null ? '--' : v.toFixed(3));

export default function ModelSpecsTab() {
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/metrics')
      .then((r) => r.json())
      .then((d) => setInfo(d.model_info))
      .catch(() => setInfo(null))
      .finally(() => setLoading(false));
  }, []);

  const m = info?.metrics;
  const rb = info?.robustness;
  const cm = info?.confusion_matrix;
  const notEvaluated = info?.status === 'NOT_EVALUATED';

  return (
    <div className="tab-pane">
      <div className="pane-header">
        <div>
          <h2>System Architecture &amp; Model Benchmarks</h2>
          <p className="pane-desc">
            Measured on a held-out test split. These figures are read from the last
            evaluation run, not hardcoded.
          </p>
        </div>
        {info?.evaluated_at && (
          <div className="quick-stats-pills">
            <span className="stat-pill">
              Evaluated: <strong>{new Date(info.evaluated_at).toLocaleDateString()}</strong>
            </span>
            <span className="stat-pill">
              Test set: <strong>{info.test_set_size} prompts</strong>
            </span>
          </div>
        )}
      </div>

      {notEvaluated && (
        <div className="card" style={{ marginBottom: 24, borderLeft: '3px solid var(--color-warning)' }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
            <AlertTriangle size={18} style={{ color: 'var(--color-warning)', flexShrink: 0 }} />
            <div>
              <strong>No evaluation results yet.</strong>
              <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>
                Run <code>python src/evaluate.py</code> to generate reproducible metrics.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="metrics-grid">
        <div className="metric-box card">
          <span className="metric-num text-success">{loading ? '…' : pct(m?.accuracy)}</span>
          <span className="metric-lbl">Accuracy</span>
        </div>
        <div className="metric-box card">
          <span className="metric-num text-cyan">{loading ? '…' : pct(m?.precision)}</span>
          <span className="metric-lbl">Precision</span>
        </div>
        <div className="metric-box card">
          <span className="metric-num text-warning">{loading ? '…' : pct(m?.recall)}</span>
          <span className="metric-lbl">Recall (Attacks Caught)</span>
        </div>
        <div className="metric-box card">
          <span className="metric-num text-primary">{loading ? '…' : num(m?.roc_auc)}</span>
          <span className="metric-lbl">ROC-AUC Score</span>
        </div>
      </div>

      {rb && (
        <div className="card" style={{ marginBottom: 24 }}>
          <span className="card-title" style={{ marginBottom: 14 }}>Evasion Robustness</span>
          <div className="metrics-grid" style={{ marginBottom: 0 }}>
            <div className="metric-box">
              <span className="metric-num text-success">{pct(rb.detection_verbatim)}</span>
              <span className="metric-lbl">Verbatim attacks caught</span>
            </div>
            <div className="metric-box">
              <span className="metric-num text-warning">{pct(rb.detection_reworded)}</span>
              <span className="metric-lbl">Reworded attacks caught</span>
            </div>
            <div className="metric-box">
              <span className="metric-num text-cyan">{num(rb.robustness_drop)}</span>
              <span className="metric-lbl">Robustness drop</span>
            </div>
            <div className="metric-box">
              <span className="metric-num text-danger">{pct(m?.false_positive_rate)}</span>
              <span className="metric-lbl">False-positive rate</span>
            </div>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 14, lineHeight: 1.6 }}>
            Attacks are paraphrased with innocuous prefixes and re-tested. The drop is how
            much detection degrades when an attacker simply rewords the prompt — lower is better.
          </p>
        </div>
      )}

      <div className="card arch-diagram-card" style={{ marginBottom: 24 }}>
        <span className="card-title" style={{ marginBottom: 16 }}>Multi-Stage Inspection Pipeline</span>
        <div className="pipeline-diagram">
          <div className="pipe-step">
            <div className="pipe-icon">👤</div>
            <div className="pipe-title">User Prompt</div>
            <div className="pipe-desc">Incoming Query</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step highlight">
            <div className="pipe-icon">🛡️</div>
            <div className="pipe-title">Gateway</div>
            <div className="pipe-desc">Auth &amp; Rate Limit</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step">
            <div className="pipe-icon">🤖</div>
            <div className="pipe-title">Sliding-Window Classifier</div>
            <div className="pipe-desc">Scores every window</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step">
            <div className="pipe-icon">⚡</div>
            <div className="pipe-title">Policy Evaluator</div>
            <div className="pipe-desc">Risk, priority &amp; reasons</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step result-step">
            <div className="pipe-icon">✅ / ❌</div>
            <div className="pipe-title">ALLOW / BLOCK</div>
            <div className="pipe-desc">Audited &amp; explained</div>
          </div>
        </div>
      </div>

      {cm && (
        <div className="card" style={{ marginBottom: 24 }}>
          <span className="card-title" style={{ marginBottom: 12 }}>Confusion Matrix</span>
          <div className="meta-info-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <div className="meta-item">
              <span className="meta-label">True Positives</span>
              <span className="meta-val">{cm.true_positives}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">True Negatives</span>
              <span className="meta-val">{cm.true_negatives}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">False Positives</span>
              <span className="meta-val">{cm.false_positives}</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">False Negatives</span>
              <span className="meta-val">{cm.false_negatives}</span>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <h3 style={{ color: 'var(--color-cyan)', marginBottom: 10, fontSize: 16 }}>
          Dataset &amp; Training
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.7 }}>
          {info?.architecture || 'DistilBERT fine-tuned'} on{' '}
          {info?.training_dataset || 'jailbreak and benign instruction corpora'}.
          Long prompts are scored with overlapping windows so a payload buried past the
          token limit is still detected.
        </p>
      </div>
    </div>
  );
}
