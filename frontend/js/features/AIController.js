import api from '../core/ApiClient.js';
import globalState from '../core/State.js';
import { toast } from '../utils/DOM.js';

const AI_MODULES = [
    { name: 'Anomaly Detection', desc: 'ML-based anomaly identification', icon: '🎯', status: 'active' },
    { name: 'NLP Processor', desc: 'Natural language threat analysis', icon: '📝', status: 'active' },
    { name: 'Predictive Analytics', desc: 'Forecast attack patterns', icon: '📈', status: 'active' },
    { name: 'Threat Clustering', desc: 'Group related IOCs', icon: '🧩', status: 'active' },
    { name: 'LLM Integration', desc: 'Gemini-powered analysis', icon: '🧠', status: 'active' },
    { name: 'Adaptive Learning', desc: 'Self-improving detection', icon: '🔄', status: 'active' },
];

export function initAI() {
    loadAIModules();

    const btnAskAI = document.getElementById('btn-ask-ai');
    if (btnAskAI) btnAskAI.onclick = askAI;

    const promptInput = document.getElementById('ai-prompt');
    if (promptInput) promptInput.onkeypress = (e) => e.key === 'Enter' && askAI();
}

async function loadAIModules() {
    const list = document.getElementById('ai-modules-list');
    if (!list) return;

    let modules = AI_MODULES;

    try {
        const data = await api('/api/v1/ai/modules');
        if (data?.modules && Array.isArray(data.modules) && data.modules.length > 0) {
            modules = data.modules;
        }
    } catch (_) { /* use fallback */ }

    list.innerHTML = modules.map(m => `
    <div class="card" style="display:flex;align-items:center;gap:12px;padding:14px">
      <span style="font-size:24px">${m.icon || '🔧'}</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:13px">${m.name}</div>
        <div style="font-size:11px;color:var(--text-muted)">${m.desc || m.description || ''}</div>
      </div>
      <span class="status-dot ${(m.status || 'active') === 'active' ? 'active' : 'pending'}"></span>
    </div>
  `).join('');
}

async function askAI() {
    const prompt = document.getElementById('ai-prompt').value.trim();
    if (!prompt) return toast('Enter a question', 'error');

    const output = document.getElementById('ai-output');
    output.innerHTML = `<span class="line-info">Analyzing: ${prompt}</span><br><div class="spinner"></div>`;

    try {
        const data = await api('/api/v1/ai/analyze', {
            method: 'POST',
            body: { data: prompt, analysis_type: 'general' }
        });
        output.innerHTML = `
      <span class="line-success">✓ AI Analysis Complete</span><br>
      <span class="line-dim">${JSON.stringify(data, null, 2)}</span>
    `;
        toast('AI analysis complete', 'success');
    } catch (e) {
        output.innerHTML = `
      <span class="line-info">Analyzing: ${prompt}</span><br>
      <span class="line-warning">AI endpoint returned: ${e.message}</span><br>
      <span class="line-dim">The AI engine is available via the API. Configure GEMINI_API_KEY for full LLM support.</span>
    `;
    }
}
