/**
 * OfSec V3 — AI Engine Page Module
 */
import { api } from '../api.js';
import { toast } from '../ui.js';

const AI_MODULES = [
    { name: 'Anomaly Detection', desc: 'ML-based anomaly identification', icon: '🎯', status: 'active' },
    { name: 'NLP Processor', desc: 'Natural language threat analysis', icon: '📝', status: 'active' },
    { name: 'Predictive Analytics', desc: 'Forecast attack patterns', icon: '📈', status: 'active' },
    { name: 'Threat Clustering', desc: 'Group related IOCs', icon: '🧩', status: 'active' },
    { name: 'LLM Integration', desc: 'Gemini-powered analysis', icon: '🧠', status: 'active' },
    { name: 'Adaptive Learning', desc: 'Self-improving detection', icon: '🔄', status: 'active' },
];

export function loadAIModules() {
    const list = document.getElementById('ai-modules-list');
    if (!list) return;
    list.innerHTML = AI_MODULES.map(m => `
    <div class="card" style="display:flex;align-items:center;gap:12px;padding:14px">
      <span style="font-size:24px">${m.icon}</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:13px">${m.name}</div>
        <div style="font-size:11px;color:var(--text-muted)">${m.desc}</div>
      </div>
      <span class="status-dot active"></span>
    </div>
  `).join('');
}

export async function askAI() {
    const prompt = document.getElementById('ai-prompt').value.trim();
    if (!prompt) return toast('Enter a question', 'error');

    const output = document.getElementById('ai-output');
    output.innerHTML = `<span class="line-info">Analyzing: ${prompt}</span><br><div class="spinner"></div>`;

    try {
        const data = await api('/api/v1/ai/analyze', { method: 'POST', body: { data: prompt, analysis_type: 'general' } });
        output.innerHTML = `<span class="line-success">✓ AI Analysis Complete</span><br>
      <span class="line-dim">${JSON.stringify(data, null, 2)}</span>`;
        toast('AI analysis complete', 'success');
    } catch (e) {
        output.innerHTML = `<span class="line-info">Analyzing: ${prompt}</span><br>
      <span class="line-warning">AI endpoint returned: ${e.message}</span><br>
      <span class="line-dim">Configure GEMINI_API_KEY for full LLM support.</span>`;
    }
}

export function initAIPage() {
    document.getElementById('btn-ask-ai')?.addEventListener('click', askAI);
}
