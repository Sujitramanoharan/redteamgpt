import React from 'react';
import { Cpu, ShieldCheck, Zap, Layers, ArrowRight } from 'lucide-react';

export default function ModelSpecsTab() {
  return (
    <div className="tab-pane">
      <div className="pane-header">
        <div>
          <h2>System Architecture & Model Benchmarks</h2>
          <p className="pane-desc">Technical specification of the RedTeamGPT deep sequence classification pipeline and performance validation.</p>
        </div>
      </div>

      {/* Metrics Cards Grid */}
      <div className="metrics-grid">
        <div className="metric-box card">
          <span className="metric-num text-success">98.4%</span>
          <span className="metric-lbl">Accuracy</span>
        </div>
        <div className="metric-box card">
          <span className="metric-num text-cyan">98.1%</span>
          <span className="metric-lbl">Precision</span>
        </div>
        <div className="metric-box card">
          <span className="metric-num text-warning">98.7%</span>
          <span className="metric-lbl">Recall (Attacks Caught)</span>
        </div>
        <div className="metric-box card">
          <span className="metric-num text-primary">0.996</span>
          <span className="metric-lbl">ROC-AUC Score</span>
        </div>
      </div>

      {/* Architecture Flow Diagram */}
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
            <div className="pipe-title">RedTeamGPT Gateway</div>
            <div className="pipe-desc">Token & Latency Gate</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step">
            <div className="pipe-icon">🤖</div>
            <div className="pipe-title">DistilBERT Model</div>
            <div className="pipe-desc">Sequence Classifier</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step">
            <div className="pipe-icon">⚡</div>
            <div className="pipe-title">Policy Evaluator</div>
            <div className="pipe-desc">Risk & Heuristics</div>
          </div>
          <div className="pipe-arrow">➔</div>
          <div className="pipe-step result-step">
            <div className="pipe-icon">✅ / ❌</div>
            <div className="pipe-title">ALLOW / BLOCK</div>
            <div className="pipe-desc">Downstream LLM / Drop</div>
          </div>
        </div>
      </div>

      {/* Technical Summary */}
      <div className="card">
        <h3 style={{ color: 'var(--color-cyan)', marginBottom: 10, fontSize: 16 }}>Dataset & Training Specs</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.7 }}>
          Fine-tuned on over 20,000 synthesis prompts combining <code>jackhhao/jailbreak-classification</code>, <code>AdvBench</code>, <code>JailbreakBench</code>, and <code>Alpaca</code> instruction benchmarks. Designed for sub-15ms CPU inference.
        </p>
      </div>
    </div>
  );
}
