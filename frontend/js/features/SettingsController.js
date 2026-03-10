import api from '../core/ApiClient.js';
import globalState from '../core/State.js';
import { toast } from '../utils/DOM.js';

const KEY_DEFS = [
  { name: 'Gemini AI', key: 'GEMINI_API_KEY', critical: true, testFn: testGemini },
  { name: 'Shodan', key: 'SHODAN_API_KEY', critical: false, testFn: testShodan },
  { name: 'VirusTotal', key: 'VIRUSTOTAL_API_KEY', critical: false, testFn: testVirusTotal },
  { name: 'AbuseIPDB', key: 'ABUSEIPDB_API_KEY', critical: false, testFn: testAbuseIPDB },
  { name: 'Censys', key: 'CENSYS_API_ID', critical: false, testFn: testCensys },
  { name: 'NVD', key: 'NVD_API_KEY', critical: false, testFn: testNVD },
  { name: 'AlienVault OTX', key: 'OTX_API_KEY', critical: false, testFn: null },
  { name: 'Hunter.io', key: 'HUNTER_API_KEY', critical: false, testFn: null },
];

let keyStatuses = {};

export function initSettings() {
  loadAccountInfo();
  loadPlatformInfo();
  loadAPIKeyStatus();

  const btnRetestKeys = document.getElementById('btn-retest-keys');
  if (btnRetestKeys) btnRetestKeys.onclick = loadAPIKeyStatus;

  const btnChangePassword = document.getElementById('btn-change-password');
  if (btnChangePassword) btnChangePassword.onclick = changePassword;
}

// ─── Account Info & Password ───
async function loadAccountInfo() {
  const el = document.getElementById('account-info');
  if (!el) return;
  try {
    const data = await api('/api/v1/auth/me');
    el.innerHTML = `
      <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px">
        <span style="color:var(--text-dim)">Email:</span> <span>${data.email}</span>
        <span style="color:var(--text-dim)">Role:</span> <span>${data.role}</span>
        <span style="color:var(--text-dim)">Name:</span> <span>${data.display_name || '—'}</span>
      </div>
    `;
  } catch (e) {
    el.innerHTML = `<span style="color:var(--accent-red)">Failed to load account info</span>`;
  }
}

async function changePassword() {
  const oldPw = document.getElementById('pw-old')?.value;
  const newPw = document.getElementById('pw-new')?.value;
  if (!oldPw || !newPw) return toast('Both fields required', 'warning');
  if (newPw.length < 8) return toast('Password must be at least 8 characters', 'warning');

  try {
    await api('/api/v1/auth/change-password', {
      method: 'POST',
      body: { old_password: oldPw, new_password: newPw },
    });
    toast('Password changed', 'success');
    document.getElementById('pw-old').value = '';
    document.getElementById('pw-new').value = '';
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  }
}

// ─── Platform Info ───
async function loadPlatformInfo() {
  const container = document.getElementById('platform-info');
  if (!container) return;

  try {
    const health = await api('/health');
    const status = await api('/api/v1/status');
    container.innerHTML = `
      <div style="font-size:13px;line-height:2">
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Version</span><span>${health.version}</span></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Environment</span><span>${health.environment}</span></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Status</span><span style="color:var(--accent-green)">${health.status}</span></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Database</span><span>${health.services?.database || 'unknown'}</span></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">API Version</span><span>${status.api_version}</span></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Modules</span><span>${Object.keys(status.modules || {}).length} active</span></div>
        <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">API Docs</span><a href="/docs" target="_blank" style="color:var(--accent-blue)">Open Swagger UI →</a></div>
      </div>
    `;
  } catch (e) {
    container.innerHTML = '<p style="color:var(--text-muted)">Unable to load platform info</p>';
  }
}

// ─── API Keys ───
async function loadAPIKeyStatus() {
  const container = document.getElementById('api-key-status');
  if (!container) return;

  renderKeyGrid(container);

  // Auto-test all testable keys
  KEY_DEFS.forEach(k => {
    if (k.testFn) {
      testKey(k.key);
    } else {
      keyStatuses[k.key] = 'untestable';
    }
  });
  renderKeyGrid(container);
}

function renderKeyGrid(container) {
  let rows = '';
  KEY_DEFS.forEach(k => {
    const s = keyStatuses[k.key] || 'idle';
    const dot = s === 'ok' ? '🟢' : s === 'error' ? '🔴' : s === 'testing' ? '🟡' : s === 'untestable' ? '🟠' : '⚪';
    const label = s === 'ok' ? 'Connected' : s === 'error' ? 'Failed / Not Set' : s === 'testing' ? 'Testing...' : s === 'untestable' ? 'Not testable' : 'Untested';
    const labelColor = s === 'ok' ? 'var(--accent-green)' : s === 'error' ? 'var(--accent-red)' : s === 'testing' ? 'var(--accent-orange)' : 'var(--text-muted)';
    const canTest = k.testFn !== null;

    rows += `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(55,65,81,0.2);border-radius:var(--radius-sm);margin-bottom:6px">`;
    rows += `<div style="display:flex;align-items:center;gap:8px"><span style="font-size:16px">${dot}</span><div><div style="font-size:13px;font-weight:500">${k.name}</div><div style="font-size:11px;color:var(--text-muted)">${k.key}</div></div></div>`;
    rows += `<div style="display:flex;align-items:center;gap:10px"><span style="font-size:11px;color:${labelColor}">${label}</span>`;

    if (canTest) {
      rows += `<button class="btn test-key-btn" data-key="${k.key}" style="padding:3px 10px;font-size:11px" ${s === 'testing' ? 'disabled' : ''}>${s === 'testing' ? '...' : 'Test'}</button>`;
    }
    rows += '</div></div>';
  });
  container.innerHTML = rows;

  // Re-bind buttons
  container.querySelectorAll('.test-key-btn').forEach(btn => {
    btn.onclick = () => testKey(btn.dataset.key);
  });
}

async function testKey(keyName) {
  const def = KEY_DEFS.find(k => k.key === keyName);
  if (!def || !def.testFn) return;

  keyStatuses[keyName] = 'testing';
  const container = document.getElementById('api-key-status');
  if (container) renderKeyGrid(container);

  try {
    const result = await def.testFn();
    keyStatuses[keyName] = result ? 'ok' : 'error';
  } catch (e) {
    keyStatuses[keyName] = 'error';
  }

  if (container) renderKeyGrid(container);
}

// ─── Key probe functions ───
async function testGemini() {
  try {
    const r = await api('/api/v1/ai/analyze/instant', { method: 'POST', body: { target: 'test', findings: [], analysis_type: 'general' } });
    return !r?.error?.toLowerCase().includes('api key');
  } catch (e) { return false; }
}

async function testShodan() {
  try {
    const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return !r?.sources?.shodan?.error;
  } catch (e) { return false; }
}

async function testVirusTotal() {
  try {
    const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return !r?.sources?.virustotal?.error;
  } catch (e) { return false; }
}

async function testAbuseIPDB() {
  try {
    const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return r?.sources?.abuseipdb !== undefined && !r?.sources?.abuseipdb?.error;
  } catch (e) { return false; }
}

async function testCensys() {
  try {
    const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return r?.sources?.censys !== undefined && !r?.sources?.censys?.error;
  } catch (e) { return false; }
}

async function testNVD() {
  try {
    const r = await api('/api/v1/ai/cve/analyze', { method: 'POST', body: ['CVE-2021-44228'] });
    return Array.isArray(r?.cves) && r.cves.length > 0;
  } catch (e) { return false; }
}
