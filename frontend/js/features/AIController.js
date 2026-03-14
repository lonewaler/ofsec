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
  if (btnAskAI) btnAskAI.onclick = () => {
    const prompt = document.getElementById('ai-prompt').value.trim();
    if (prompt) askBrain(prompt);
  };

  const promptInput = document.getElementById('ai-prompt');
  if (promptInput) promptInput.onkeypress = (e) => {
    if (e.key === 'Enter') {
      const prompt = promptInput.value.trim();
      if (prompt) askBrain(prompt);
    }
  };
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

async function askBrain(goal) {
  if (!goal) return toast('Enter a question', 'error');

  const output = document.getElementById('ai-output');
  if (!output) return;

  output.innerHTML = ''; // clear previous
  termLine(output, `Agentic Brain: Planning to "${goal}"...`, 'info');

  try {
    termLine(output, 'Fetching execution plan from LLM...', 'dim');
    const data = await api('/api/v1/brain/plan', {
      method: 'POST',
      body: { goal: goal }
    });

    if (data && data.status === 'success' && data.plan) {
      const { tool, args } = data.plan;
      termLine(output, `✓ Plan generated: ${tool} ${args.join(' ')}`, 'success');
      termLine(output, `Executing ${tool}...`, 'info');

      executePlan(tool, args, output);
    } else {
      termLine(output, `✗ Brain Error: ${data.message || 'Unknown error'}`, 'error');
      toast('Brain planning failed', 'error');
    }

  } catch (e) {
    termLine(output, `✗ Request Error: ${e.message}`, 'error');
  }
}


function executePlan(tool, args, terminalEl) {
  // Construct websocket URL relative to current host
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  // The backend uses 8000 port locally but usually proxied or same host
  const apiHost = window.location.host;
  const wsUrl = `${wsProtocol}//${apiHost}/api/v1/cli/ws/exec`;

  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    termLine(terminalEl, `[WebSocket Connected to ${wsUrl}]`, 'success');
    // Send execution payload
    ws.send(JSON.stringify({ tool, args }));
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'stdout') {
        termLine(terminalEl, msg.data);
      } else if (msg.type === 'error') {
        termLine(terminalEl, `Error: ${msg.data}`, 'error');
      } else if (msg.type === 'status') {
        termLine(terminalEl, `Status: ${msg.data}`, 'success');
      }
    } catch (e) {
      termLine(terminalEl, event.data);
    }
  };

  ws.onerror = (err) => {
    termLine(terminalEl, 'WebSocket Error occurred.', 'error');
  };

  ws.onclose = () => {
    termLine(terminalEl, '[WebSocket Disconnected]', 'dim');
  };
}

