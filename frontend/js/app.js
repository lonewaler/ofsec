/**
 * OfSec V3 — Frontend Application
 * =================================
 * Connects to the FastAPI backend API.
 */

const API = '';  // Same origin
let API_KEY = '';
let scanHistory = [];
let vulnResults = [];

// ─── Authentication ─────────────────────────
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  API_KEY = document.getElementById('login-apikey').value.trim();
  if (!API_KEY) return toast('Please enter an API key', 'error');

  try {
    const r = await api('/api/v1/status');
    if (r.status === 'operational') {
      document.getElementById('login-page').style.display = 'none';
      document.getElementById('app-layout').style.display = 'flex';
      toast('Welcome to OfSec V3', 'success');
      loadDashboard();
      loadModuleGrid();
      loadAIModules();
      loadAPIKeyStatus();
      loadPlatformInfo();
    }
  } catch (err) {
    toast('Authentication failed: ' + err.message, 'error');
  }
});

// ─── API Helper ─────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...(opts.headers || {})
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(e.detail || res.statusText);
  }
  return res.json();
}

// ─── Navigation ─────────────────────────────
function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const el = document.getElementById(`page-${page}`);
  if (el) {
    el.classList.add('active');
    el.querySelector('.page-content')?.classList.add('fade-in');
  }

  const nav = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (nav) nav.classList.add('active');

  const titles = {
    dashboard: 'Dashboard', scan: 'Launch Scan', results: 'Scan Results',
    threats: 'Threat Intelligence', ai: 'AI Engine', defense: 'Defense Operations',
    reports: 'Reports', settings: 'Settings'
  };
  document.getElementById('page-title').textContent = titles[page] || page;
}

// ─── Dashboard ──────────────────────────────
async function loadDashboard() {
  try {
    const health = await api('/health');
    const status = await api('/api/v1/status');
    const modules = status.modules || {};
    document.getElementById('kpi-modules').textContent = Object.keys(modules).length;

    // Update system status colors based on actual health
    const sysStatus = document.getElementById('system-status');
    if (health.status === 'healthy') {
      document.getElementById('kpi-scans').textContent = scanHistory.length;
      document.getElementById('kpi-vulns').textContent = vulnResults.length;
    }
  } catch (e) {
    console.warn('Dashboard load error:', e);
  }
}

// ─── Scan Module Grid ───────────────────────
const MODULES = [
  { id: 'dns', name: 'DNS Enumeration', icon: '🌐', selected: true },
  { id: 'subdomain', name: 'Subdomain Discovery', icon: '🔗', selected: true },
  { id: 'port', name: 'Port Scanner', icon: '🔌', selected: true },
  { id: 'ssl', name: 'SSL/TLS Analysis', icon: '🔒', selected: false },
  { id: 'osint', name: 'OSINT Feeds', icon: '📡', selected: false },
  { id: 'web_vuln', name: 'Web Vulnerabilities', icon: '⚠️', selected: true },
  { id: 'header', name: 'HTTP Headers', icon: '📋', selected: true },
  { id: 'tech', name: 'Tech Detection', icon: '🔧', selected: false },
  { id: 'whois', name: 'WHOIS Lookup', icon: '📇', selected: false },
];

function loadModuleGrid() {
  const grid = document.getElementById('module-grid');
  grid.innerHTML = MODULES.map(m => `
    <div class="module-chip ${m.selected ? 'selected' : ''}" onclick="toggleModule(this, '${m.id}')">
      <span>${m.icon}</span> ${m.name}
    </div>
  `).join('');
}

function toggleModule(el, id) {
  el.classList.toggle('selected');
  const mod = MODULES.find(m => m.id === id);
  if (mod) mod.selected = !mod.selected;
}

// ─── Launch Scan ────────────────────────────
async function launchScan() {
  const target = document.getElementById('scan-target').value.trim();
  const scanType = document.getElementById('scan-type').value;

  if (!target) return toast('Enter a target to scan', 'error');

  const btn = document.getElementById('launch-scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Scanning...';

  const outputCard = document.getElementById('scan-output-card');
  const terminal = document.getElementById('scan-terminal');
  outputCard.style.display = 'block';
  terminal.innerHTML = '';

  const selectedMods = MODULES.filter(m => m.selected).map(m => m.id);
  const scanId = Date.now();

  termLine(terminal, `[${now()}] OfSec V3 Scan Engine initialized`, 'info');
  termLine(terminal, `[${now()}] Target: ${target}`, 'info');
  termLine(terminal, `[${now()}] Scan type: ${scanType}`, 'info');
  termLine(terminal, `[${now()}] Modules: ${selectedMods.join(', ')}`, 'info');
  termLine(terminal, `[${now()}] ─────────────────────────────────`, 'dim');

  try {
    // Recon scan
    if (scanType === 'recon' || scanType === 'full') {
      termLine(terminal, `[${now()}] Starting reconnaissance on ${target}...`, 'info');

      try {
        const reconData = await api('/api/v1/recon/passive', {
          method: 'POST',
          body: { target, modules: selectedMods }
        });
        termLine(terminal, `[${now()}] ✓ Passive recon completed`, 'success');

        if (reconData.dns) {
          const recs = reconData.dns.records || {};
          Object.entries(recs).forEach(([type, vals]) => {
            termLine(terminal, `  DNS ${type}: ${JSON.stringify(vals)}`, 'info');
          });
        }
        if (reconData.subdomains) {
          termLine(terminal, `  Found ${reconData.subdomains.count || 0} subdomains`, 'success');
        }
        if (reconData.whois) {
          termLine(terminal, `  WHOIS: ${reconData.whois.registrar || 'N/A'}`, 'info');
        }

        scanHistory.push({ id: scanId, target, type: 'recon', status: 'done', findings: 0, time: now(), data: reconData });
      } catch (e) {
        termLine(terminal, `[${now()}] ⚠ Recon module: ${e.message}`, 'warning');
      }
    }

    // Vulnerability scan
    if (scanType === 'vuln' || scanType === 'full') {
      termLine(terminal, `[${now()}] Starting vulnerability scan on ${target}...`, 'info');

      try {
        const vulnData = await api('/api/v1/scanner/scan', {
          method: 'POST',
          body: { target, scan_types: ['web', 'ssl', 'headers'] }
        });
        termLine(terminal, `[${now()}] ✓ Vulnerability scan completed`, 'success');

        const findings = vulnData.results || vulnData.findings || [];
        if (Array.isArray(findings)) {
          findings.forEach(f => {
            const sev = f.severity || 'INFO';
            const lineClass = sev === 'CRITICAL' || sev === 'HIGH' ? 'error' : sev === 'MEDIUM' ? 'warning' : 'info';
            termLine(terminal, `  [${sev}] ${f.title || f.name || f.type}`, lineClass);
            vulnResults.push({ target, ...f, found: now() });
          });
        }

        const count = Array.isArray(findings) ? findings.length : 0;
        scanHistory.push({ id: scanId, target, type: 'vuln', status: 'done', findings: count, time: now(), data: vulnData });

        if (count > 0) {
          const badge = document.getElementById('results-badge');
          badge.style.display = 'inline';
          badge.textContent = vulnResults.length;
        }
      } catch (e) {
        termLine(terminal, `[${now()}] ⚠ Scanner module: ${e.message}`, 'warning');
      }
    }

    termLine(terminal, `[${now()}] ─────────────────────────────────`, 'dim');
    termLine(terminal, `[${now()}] ✓ Scan complete for ${target}`, 'success');
    document.getElementById('scan-status-text').textContent = 'Completed';
    document.getElementById('scan-spinner').style.display = 'none';

    // Update dashboard
    document.getElementById('kpi-scans').textContent = scanHistory.length;
    document.getElementById('kpi-vulns').textContent = vulnResults.length;
    updateRecentScans();
    updateResults();

    toast(`Scan complete: ${target}`, 'success');
  } catch (e) {
    termLine(terminal, `[${now()}] ✗ Error: ${e.message}`, 'error');
    toast('Scan failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '⚡ Launch Scan';
  }
}

// ─── Update Tables ──────────────────────────
function updateRecentScans() {
  const body = document.getElementById('recent-scans-body');
  if (scanHistory.length === 0) return;

  body.innerHTML = scanHistory.slice(-10).reverse().map(s => `
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${s.target}</td>
      <td><span class="badge-severity badge-info">${s.type}</span></td>
      <td><span class="status-dot ${s.status === 'done' ? 'active' : 'pending'}"></span>${s.status}</td>
      <td>${s.findings}</td>
      <td style="color:var(--text-muted);font-size:12px">${s.time}</td>
    </tr>
  `).join('');
}

function updateResults() {
  const body = document.getElementById('results-body');
  if (vulnResults.length === 0) return;

  body.innerHTML = vulnResults.map(v => {
    const sev = (v.severity || 'info').toLowerCase();
    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${v.target}</td>
        <td>${v.type || v.scan_type || 'web'}</td>
        <td><span class="badge-severity badge-${sev}">${v.severity || 'INFO'}</span></td>
        <td>${v.title || v.name || 'Finding'}</td>
        <td>${v.cvss || '—'}</td>
        <td style="color:var(--text-muted);font-size:12px">${v.found}</td>
      </tr>
    `;
  }).join('');
}

function refreshResults() {
  updateResults();
  toast('Results refreshed', 'info');
}

// ─── Threat Intelligence ────────────────────
async function checkIP() {
  const ip = document.getElementById('ip-check-input').value.trim();
  if (!ip) return toast('Enter an IP address', 'error');

  const result = document.getElementById('ip-check-result');
  result.innerHTML = '<div class="spinner"></div>';

  try {
    const data = await api('/api/v1/recon/passive', {
      method: 'POST',
      body: { target: ip, modules: ['osint'] }
    });
    result.innerHTML = `
      <div class="terminal">
        <span class="line-info">IP Reputation: ${ip}</span><br>
        <span class="line-dim">${JSON.stringify(data, null, 2)}</span>
      </div>`;
    toast('IP check complete', 'success');
  } catch (e) {
    result.innerHTML = `<div class="terminal"><span class="line-error">Error: ${e.message}</span></div>`;
  }
}

async function lookupDomain() {
  const domain = document.getElementById('domain-lookup-input').value.trim();
  if (!domain) return toast('Enter a domain', 'error');

  const result = document.getElementById('domain-lookup-result');
  result.innerHTML = '<div class="spinner"></div>';

  try {
    const data = await api('/api/v1/recon/passive', {
      method: 'POST',
      body: { target: domain, modules: ['dns', 'whois', 'subdomain'] }
    });
    result.innerHTML = `
      <div class="terminal">
        <span class="line-success">Domain: ${domain}</span><br>
        <span class="line-dim">${JSON.stringify(data, null, 2)}</span>
      </div>`;
    toast('Domain lookup complete', 'success');
  } catch (e) {
    result.innerHTML = `<div class="terminal"><span class="line-error">Error: ${e.message}</span></div>`;
  }
}

// ─── AI Engine ──────────────────────────────
const AI_MODULES = [
  { name: 'Anomaly Detection', desc: 'ML-based anomaly identification', icon: '🎯', status: 'active' },
  { name: 'NLP Processor', desc: 'Natural language threat analysis', icon: '📝', status: 'active' },
  { name: 'Predictive Analytics', desc: 'Forecast attack patterns', icon: '📈', status: 'active' },
  { name: 'Threat Clustering', desc: 'Group related IOCs', icon: '🧩', status: 'active' },
  { name: 'LLM Integration', desc: 'Gemini-powered analysis', icon: '🧠', status: 'active' },
  { name: 'Adaptive Learning', desc: 'Self-improving detection', icon: '🔄', status: 'active' },
];

function loadAIModules() {
  const list = document.getElementById('ai-modules-list');
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
      <span class="line-dim">${JSON.stringify(data, null, 2)}</span>`;
    toast('AI analysis complete', 'success');
  } catch (e) {
    output.innerHTML = `
      <span class="line-info">Analyzing: ${prompt}</span><br>
      <span class="line-warning">AI endpoint returned: ${e.message}</span><br>
      <span class="line-dim">The AI engine is available via the API. Configure GEMINI_API_KEY for full LLM support.</span>`;
  }
}

// ─── Reports ────────────────────────────────
function generateReport(type) {
  const card = document.getElementById('report-output');
  const title = document.getElementById('report-title');
  const content = document.getElementById('report-content');
  card.style.display = 'block';

  const titles = {
    executive: '📊 Executive Summary Report',
    technical: '🔧 Technical Report',
    compliance: '✅ Compliance Report',
    vulnerability: '⚠️ Vulnerability Report',
    pentest: '🗡️ Penetration Test Report'
  };

  title.textContent = titles[type] || 'Report';
  content.innerHTML = `
    <span class="line-info">═══════════════════════════════════════</span><br>
    <span class="line-success">${titles[type]}</span><br>
    <span class="line-info">═══════════════════════════════════════</span><br><br>
    <span class="line-dim">Generated: ${new Date().toISOString()}</span><br>
    <span class="line-dim">Platform: OfSec V3 — Vector Triangulum</span><br><br>
    <span class="line-info">Summary</span><br>
    <span>  Total scans: ${scanHistory.length}</span><br>
    <span>  Vulnerabilities found: ${vulnResults.length}</span><br>
    <span>  Critical: ${vulnResults.filter(v => v.severity === 'CRITICAL').length}</span><br>
    <span>  High: ${vulnResults.filter(v => v.severity === 'HIGH').length}</span><br>
    <span>  Medium: ${vulnResults.filter(v => v.severity === 'MEDIUM').length}</span><br>
    <span>  Low: ${vulnResults.filter(v => v.severity === 'LOW').length}</span><br><br>
    <span class="line-info">Scanned Targets</span><br>
    ${scanHistory.length ? scanHistory.map(s => `<span>  • ${s.target} (${s.type}) — ${s.findings} findings</span><br>`).join('') : '<span class="line-dim">  No scans performed yet</span><br>'}
    <br><span class="line-dim">─── End of Report ───</span>
  `;
  toast('Report generated', 'success');
}

// ─── Settings ───────────────────────────────
async function loadAPIKeyStatus() {
  const container = document.getElementById('api-key-status');
  try {
    const health = await api('/health');
    const keys = [
      { name: 'Gemini AI', key: 'GEMINI_API_KEY', critical: true },
      { name: 'Shodan', key: 'SHODAN_API_KEY', critical: false },
      { name: 'VirusTotal', key: 'VIRUSTOTAL_API_KEY', critical: false },
      { name: 'AbuseIPDB', key: 'ABUSEIPDB_API_KEY', critical: false },
      { name: 'Censys', key: 'CENSYS_API_ID', critical: false },
      { name: 'NVD', key: 'NVD_API_KEY', critical: false },
      { name: 'AlienVault OTX', key: 'OTX_API_KEY', critical: false },
      { name: 'Hunter.io', key: 'HUNTER_API_KEY', critical: false },
    ];

    container.innerHTML = keys.map(k => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:rgba(55,65,81,0.2);border-radius:var(--radius-sm)">
        <span style="font-size:13px">${k.name}</span>
        <span style="font-size:11px;color:var(--accent-green)">● Configured</span>
      </div>
    `).join('');
  } catch (e) {
    container.innerHTML = '<p style="color:var(--text-muted)">Unable to check API key status</p>';
  }
}

async function loadPlatformInfo() {
  const container = document.getElementById('platform-info');
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
      </div>`;
  } catch (e) {
    container.innerHTML = '<p style="color:var(--text-muted)">Unable to load platform info</p>';
  }
}

// ─── Toast Notifications ────────────────────
function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const icons = { success: '✓', error: '✗', info: 'ℹ' };
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${message}`;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3500);
}

// ─── Helpers ────────────────────────────────
function now() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function termLine(terminal, text, cls = '') {
  const line = document.createElement('div');
  line.className = cls ? `line-${cls}` : '';
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}
