/**
 * OfSec V3 — Frontend Application
 * =================================
 * Connects to the FastAPI backend API.
 */

const API = '';  // Same origin
let API_KEY = 'dev-api-key';  // WebSocket auth token — matches settings.API_KEY
let scanHistory = [];
let vulnResults = [];

// ─── Global Error Handlers ──────────────────
// Catches ALL unhandled JS errors and reports them to the backend
window.onerror = function (message, source, lineno, colno, error) {
  console.error('[OfSec] Unhandled error:', message, source, lineno);
  reportErrorToBackend({
    message: String(message),
    source: `${source}:${lineno}:${colno}`,
    stack: error?.stack || '',
    url: window.location.href
  });
  // Show user-friendly toast
  if (typeof toast === 'function') {
    toast('An unexpected error occurred. Check logs for details.', 'error');
  }
  return false; // Don't suppress the error in console
};

window.addEventListener('unhandledrejection', function (event) {
  console.error('[OfSec] Unhandled promise rejection:', event.reason);
  reportErrorToBackend({
    message: 'Unhandled promise rejection: ' + String(event.reason?.message || event.reason),
    source: 'promise',
    stack: event.reason?.stack || '',
    url: window.location.href
  });
  if (typeof toast === 'function') {
    toast('A background operation failed: ' + (event.reason?.message || 'Unknown error'), 'error');
  }
});

function reportErrorToBackend(errorData) {
  // Fire-and-forget — don't let this reporting itself cause errors
  try {
    fetch(API + '/api/v1/log/error', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
      body: JSON.stringify({
        message: errorData.message,
        source: errorData.source || 'frontend',
        stack: errorData.stack || '',
        url: errorData.url || window.location.href,
        user_agent: navigator.userAgent
      })
    }).catch(() => { }); // Silently fail if logging endpoint is down
  } catch (e) { /* ignore */ }
}

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

      // Navigate to hash page or default to dashboard
      const hashPage = location.hash.replace('#', '');
      const validPages = ['dashboard', 'scan', 'results', 'threats', 'ai', 'defense', 'reports', 'settings'];
      navigate(validPages.includes(hashPage) ? hashPage : 'dashboard');

      loadDashboard();
      loadPersistedData();
      loadModuleGrid();
      loadAIModules();
      loadAPIKeyStatus();
      loadPlatformInfo();
      loadDLQ();

      // Global polling
      setInterval(() => {
        loadDLQ();
        // and other global polls if any
      }, 30000); // Check DLQ every 30 seconds
    }
  } catch (err) {
    toast('Authentication failed: ' + err.message, 'error');
  }
});

// ─── API Helper ─────────────────────────────
async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(API + path, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
        ...(opts.headers || {})
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
  } catch (networkErr) {
    // Network error (server down, CORS, etc.)
    const errMsg = 'Cannot connect to server. Is the backend running?';
    toast(errMsg, 'error');
    reportErrorToBackend({ message: errMsg, source: 'api:' + path });
    throw new Error(errMsg);
  }

  // Handle rate limiting with a visible countdown
  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('Retry-After') || '60', 10);
    showRateLimitToast(retryAfter);
    throw new Error(`Rate limited. Retry in ${retryAfter}s`);
  }

  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: res.statusText }));
    const errMsg = e.error || e.detail || e.message || res.statusText;
    // Show user-friendly error for common status codes
    if (res.status === 401 || res.status === 403) {
      toast('Authentication failed — check your API key', 'error');
    } else if (res.status === 404) {
      toast('Resource not found: ' + path, 'error');
    } else if (res.status >= 500) {
      toast('Server error: ' + errMsg, 'error');
    } else {
      toast('Request failed: ' + errMsg, 'error');
    }
    throw new Error(errMsg);
  }
  return res.json();
}

// Rate limit countdown toast
function showRateLimitToast(seconds) {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast toast-error';
  el.style.cssText = 'min-width:260px;padding:12px 16px';
  container.appendChild(el);

  let remaining = seconds;
  function tick() {
    el.innerHTML = `⏱ Rate limited — retry in <strong>${remaining}s</strong>`;
    if (remaining <= 0) {
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 300);
    } else {
      remaining--;
      setTimeout(tick, 1000);
    }
  }
  tick();
}

// ─── Navigation (with URL hash routing) ─────
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

  // Update URL hash (without triggering hashchange listener)
  if (location.hash !== '#' + page) {
    history.replaceState(null, '', '#' + page);
  }

  // Start/stop alert polling based on active page
  if (page === 'defense') {
    startAlertPolling();
  } else {
    stopAlertPolling();
  }

  // Load queue status when viewing scan page
  if (page === 'scan') {
    loadQueueStatus();
  }

  // Load settings sub-panels when visiting settings page
  if (page === 'settings') {
    loadSchedules();
    loadAccountInfo();
    loadIntelSweepStatus();
    loadNotifConfig();
  }
}

// Handle browser back/forward and direct URL hash navigation
window.addEventListener('hashchange', function () {
  const page = location.hash.replace('#', '') || 'dashboard';
  const validPages = ['dashboard', 'scan', 'results', 'threats', 'ai', 'defense', 'reports', 'settings'];
  if (validPages.includes(page)) {
    navigate(page);
  }
});

// Global click delegation for navigation links
document.addEventListener('click', function (e) {
  // Find closest element with data-page attribute
  const navItem = e.target.closest('[data-page]');
  if (navItem) {
    const page = navItem.getAttribute('data-page');
    if (page) {
      e.preventDefault();
      navigate(page);
    }
  }
});

window.addEventListener('beforeunload', stopAlertPolling);
document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && typeof closeCVEPanel === 'function') closeCVEPanel(); });

// ─── Dashboard ──────────────────────────────
async function loadDashboard() {
  try {
    const [health, status] = await Promise.all([
      api('/health'),
      api('/api/v1/status')
    ]);

    const modules = status.modules || {};
    const moduleCount = Object.keys(modules).length;

    document.getElementById('kpi-modules').textContent = moduleCount || '—';
    document.getElementById('kpi-scans').textContent = scanHistory.length;
    document.getElementById('kpi-vulns').textContent = vulnResults.length;

    // Count critical findings
    const criticalCount = vulnResults.filter(v =>
      v.severity === 'CRITICAL' || v.severity === 'HIGH'
    ).length;
    const kpiAlerts = document.getElementById('kpi-alerts');
    if (kpiAlerts) {
      kpiAlerts.textContent = criticalCount;
      kpiAlerts.style.color = criticalCount > 0 ? 'var(--accent-red)' : '';
    }

    // System status indicator
    const sysStatusEl = document.getElementById('system-status');
    if (sysStatusEl && health.status === 'healthy') {
      const services = [
        { name: 'API', status: 'Online' },
        { name: 'Database', status: health.services?.database || 'connected' },
        ...Object.entries(modules).map(([name, avail]) => ({
          name: name.charAt(0).toUpperCase() + name.slice(1),
          status: avail === 'available' ? 'Ready' : 'Offline'
        }))
      ];
      sysStatusEl.innerHTML = services.map(s => `
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color)">
          <span style="color:var(--text-secondary)">${s.name}</span>
          <span style="color:var(--accent-green)">● ${s.status}</span>
        </div>
      `).join('');
    }

    // Update IOC count
    const kpiIocs = document.getElementById('kpi-iocs');
    if (kpiIocs) kpiIocs.textContent = iocHistory.length;
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

// ─── Scan Progress Helpers ──────────────────
function termProgress(terminal, label, percent) {
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  termLine(terminal, `  [${bar}] ${percent}% — ${label}`, 'info');
}

function renderVulnSummary(terminal, findings) {
  if (!Array.isArray(findings) || findings.length === 0) {
    termLine(terminal, '  No vulnerabilities found.', 'success');
    return;
  }
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => { counts[f.severity?.toUpperCase()] = (counts[f.severity?.toUpperCase()] || 0) + 1; });
  termLine(terminal, '  ┌─ Vulnerability Summary ─────────────────', 'info');
  Object.entries(counts).filter(([, v]) => v > 0).forEach(([k, v]) => {
    const icon = k === 'CRITICAL' ? '🔴' : k === 'HIGH' ? '🟠' : k === 'MEDIUM' ? '🟡' : k === 'LOW' ? '🔵' : 'ℹ️';
    termLine(terminal, `  │ ${icon} ${k.padEnd(8)} ${v} finding${v !== 1 ? 's' : ''}`,
      k === 'CRITICAL' || k === 'HIGH' ? 'error' : k === 'MEDIUM' ? 'warning' : 'dim');
  });
  termLine(terminal, '  └──────────────────────────────────────────', 'info');
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
    // Recon scan — uses SSE streaming
    if (scanType === 'recon' || scanType === 'full') {
      termLine(terminal, `[${now()}] Starting reconnaissance on ${target}...`, 'info');
      termLine(terminal, `[${now()}] Streaming results in real-time...`, 'dim');

      try {
        // Start scan in streaming mode
        const initRes = await api('/api/v1/recon/passive?stream=true', {
          method: 'POST',
          body: { target, modules: selectedMods }
        });

        const dbScanId = initRes.scan_id;
        termLine(terminal, `[${now()}] Scan started (ID: ${dbScanId}) -- streaming results...`, 'success');

        // Open SSE stream
        await streamScanResults(dbScanId, terminal, target);

      } catch (e) {
        termLine(terminal, `[${now()}] SSE not available, falling back to blocking mode...`, 'warning');
        // Fallback: blocking mode
        try {
          const reconData = await api('/api/v1/recon/passive', {
            method: 'POST',
            body: { target, modules: selectedMods }
          });
          termLine(terminal, `[${now()}] Passive recon completed`, 'success');

          const dns = reconData?.dns || reconData?.results?.dns || {};
          const recs = dns?.records || dns || {};
          if (recs && typeof recs === 'object') {
            Object.entries(recs).forEach(([type, vals]) => {
              if (type !== 'error') termLine(terminal, `  DNS ${type}: ${Array.isArray(vals) ? vals.join(', ') : vals}`, 'info');
            });
          }

          scanHistory.push({ id: scanId, target, type: 'recon', status: 'done', findings: 0, time: now(), data: reconData });
        } catch (fallbackErr) {
          termLine(terminal, `[${now()}] Recon module: ${fallbackErr.message}`, 'warning');
        }
      }
    }

    // Vulnerability scan
    if (scanType === 'vuln' || scanType === 'full') {
      termLine(terminal, `[${now()}] Starting vulnerability scan on ${target}...`, 'info');
      termProgress(terminal, 'Initializing scanner', 0);

      try {
        termProgress(terminal, 'Scanning web, SSL, headers...', 25);
        const vulnData = await api('/api/v1/scanner/scan', {
          method: 'POST',
          body: { target, scan_types: ['web', 'ssl', 'headers'] }
        });
        termProgress(terminal, 'Analyzing findings', 75);
        termLine(terminal, `[${now()}] Vulnerability scan completed`, 'success');

        const findings = vulnData?.results || vulnData?.findings || [];
        if (Array.isArray(findings)) {
          findings.forEach(f => {
            const sev = f.severity || 'INFO';
            const lineClass = sev === 'CRITICAL' || sev === 'HIGH' ? 'error' : sev === 'MEDIUM' ? 'warning' : 'info';
            termLine(terminal, `  [${sev}] ${f.title || f.name || f.type}`, lineClass);
            vulnResults.push({ target, ...f, found: now() });
          });
          renderVulnSummary(terminal, findings);
        }

        termProgress(terminal, 'Scan complete', 100);
        const count = Array.isArray(findings) ? findings.length : 0;
        scanHistory.push({ id: scanId, target, type: 'vuln', status: 'done', findings: count, time: now(), data: vulnData });

        if (count > 0) {
          const badge = document.getElementById('results-badge');
          badge.style.display = 'inline';
          badge.textContent = vulnResults.length;
        }
      } catch (e) {
        termLine(terminal, `[${now()}] Scanner module: ${e.message}`, 'warning');
      }
    }

    termLine(terminal, `[${now()}] ─────────────────────────────────`, 'dim');
    termLine(terminal, `[${now()}] Scan complete for ${target}`, 'success');
    document.getElementById('scan-status-text').textContent = 'Completed';
    document.getElementById('scan-spinner').style.display = 'none';

    // Update dashboard
    document.getElementById('kpi-scans').textContent = scanHistory.length;
    document.getElementById('kpi-vulns').textContent = vulnResults.length;
    updateRecentScans();
    updateResults();
    if (typeof updateDashboardKPIs === 'function') updateDashboardKPIs();

    toast(`Scan complete: ${target}`, 'success');
  } catch (e) {
    termLine(terminal, `[${now()}] Error: ${e.message}`, 'error');
    toast('Scan failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '⚡ Launch Scan';
  }
}

function streamScanResults(scanId, terminal, target) {
  return new Promise((resolve) => {
    const wsUrl = `ws://${location.host}/api/v1/recon/ws/${scanId}?token=${API_KEY}`;
    let ws;

    try { ws = new WebSocket(wsUrl); }
    catch (e) {
      termLine(terminal, `[${now()}] WebSocket unavailable`, 'warning');
      return resolve();
    }

    // Store reference for control buttons
    window._activeScanWS = window._activeScanWS || {};
    window._activeScanWS[scanId] = ws;

    // Inject pause / resume / cancel controls above terminal
    const ctrlId = `scan-ctrl-${scanId}`;
    if (!document.getElementById(ctrlId)) {
      const ctrl = document.createElement('div');
      ctrl.id = ctrlId;
      ctrl.style.cssText = 'display:flex;gap:8px;margin-bottom:8px';
      ctrl.innerHTML = `
        <button id="btn-pause-${scanId}" class="btn" style="font-size:11px;padding:4px 12px"
          onclick="wsScanPause('${scanId}')">⏸ Pause</button>
        <button id="btn-resume-${scanId}" class="btn" style="font-size:11px;padding:4px 12px;display:none"
          onclick="wsScanResume('${scanId}')">▶ Resume</button>
        <button class="btn" style="font-size:11px;padding:4px 12px;
          background:rgba(239,68,68,0.15);border-color:var(--accent-red);color:var(--accent-red)"
          onclick="wsScanCancel('${scanId}')">✕ Cancel</button>
      `;
      terminal.parentElement?.insertBefore(ctrl, terminal);
    }

    ws.onmessage = ({ data }) => {
      let event;
      try { event = JSON.parse(data); } catch { return; }

      if (event.type === 'module_complete') {
        const pct = Math.round((event.index / event.total) * 100);
        termLine(terminal,
          `[${now()}] ✓ ${event.module.replace(/_/g, ' ')}` +
          ` — ${event.findings_count} finding${event.findings_count !== 1 ? 's' : ''}  [${pct}%]`,
          event.findings_count > 0 ? 'warning' : 'success'
        );
        const findings = event.data?.findings || event.data?.vulnerabilities || [];
        findings.slice(0, 3).forEach(f => {
          const sev = (f.severity || 'INFO').toUpperCase();
          const cls = ['CRITICAL', 'HIGH'].includes(sev) ? 'error'
            : sev === 'MEDIUM' ? 'warning' : 'dim';
          termLine(terminal, `    [${sev}] ${f.title || f.name || f.type || 'Finding'}`, cls);
          vulnResults.push({ target, ...f, found: now() });
        });
        if (findings.length > 3)
          termLine(terminal, `    ... and ${findings.length - 3} more`, 'dim');

      } else if (event.type === 'ack') {
        const icons = { cancel: '🛑', pause: '⏸', resume: '▶' };
        termLine(terminal, `[${now()}] ${icons[event.action] || '•'} ${event.status}`, 'warning');
        if (event.action === 'pause') {
          document.getElementById(`btn-pause-${scanId}`)?.style.setProperty('display', 'none');
          document.getElementById(`btn-resume-${scanId}`)?.style.removeProperty('display');
        } else if (event.action === 'resume') {
          document.getElementById(`btn-resume-${scanId}`)?.style.setProperty('display', 'none');
          document.getElementById(`btn-pause-${scanId}`)?.style.removeProperty('display');
        }

      } else if (event.type === 'module_error') {
        termLine(terminal, `[${now()}] ⚠ ${event.module}: ${event.error}`, 'warning');

      } else if (event.type === 'cancelled') {
        termLine(terminal,
          `[${now()}] 🛑 Scan cancelled — ${event.modules_completed} module(s) run, ` +
          `${event.findings_so_far} finding(s) saved`, 'warning');
        _cleanupScanWS(scanId);
        toast('Scan cancelled', 'info');
        resolve();

      } else if (event.type === 'done') {
        termLine(terminal, `[${now()}] ───────────────────────────────────`, 'dim');
        termLine(terminal, `[${now()}] ✓ Scan complete — ${event.total_findings} total findings`, 'success');
        scanHistory.push({
          id: event.scan_id, target, type: 'recon',
          status: 'done', findings: event.total_findings, time: now(),
        });
        updateScanHistory?.();
        updateResults?.();
        updateDashboardKPIs?.();
        _cleanupScanWS(scanId);
        toast('Scan complete', 'success');
        resolve();

      } else if (event.type === 'error') {
        termLine(terminal, `[${now()}] ✗ ${event.error}`, 'error');
        _cleanupScanWS(scanId);
        resolve();

      } else if (event.type === 'ping') {
        ws.send(JSON.stringify({ action: 'ping' }));
      }
    };

    ws.onerror = () => {
      termLine(terminal, `[${now()}] WebSocket error — scan continues server-side`, 'warning');
      _cleanupScanWS(scanId);
      resolve();
    };

    ws.onclose = (e) => {
      if (e.code === 4001)
        termLine(terminal, `[${now()}] ✗ WebSocket auth failed`, 'error');
      document.getElementById(`scan-ctrl-${scanId}`)?.remove();
      resolve();
    };

    // 10-minute safety timeout
    setTimeout(() => {
      if (ws.readyState === WebSocket.OPEN) {
        termLine(terminal, `[${now()}] Stream timeout after 10min`, 'warning');
        ws.close();
        resolve();
      }
    }, 600_000);
  });
}

function _cleanupScanWS(scanId) {
  const ws = window._activeScanWS?.[scanId];
  if (ws?.readyState === WebSocket.OPEN) ws.close();
  delete window._activeScanWS?.[scanId];
  document.getElementById(`scan-ctrl-${scanId}`)?.remove();
}
function wsScanPause(id) { window._activeScanWS?.[id]?.send(JSON.stringify({ action: 'pause' })); }
function wsScanResume(id) { window._activeScanWS?.[id]?.send(JSON.stringify({ action: 'resume' })); }
function wsScanCancel(id) { window._activeScanWS?.[id]?.send(JSON.stringify({ action: 'cancel' })); }

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
    const cveMatch = (v.cve || v.title || v.name || '').match(/CVE-\d{4}-\d{4,}/i);
    const cveId = cveMatch ? cveMatch[0].toUpperCase() : null;
    const cveLink = cveId
      ? '<span onclick="openCVEPanel(\'' + cveId + '\')" style="margin-left:6px;background:rgba(59,130,246,0.2);color:var(--accent-blue);padding:1px 6px;border-radius:3px;font-size:10px;font-family:monospace;cursor:pointer;border:1px solid rgba(59,130,246,0.3)" title="View CVE detail">' + cveId + ' ↗</span>'
      : '';
    return `
      <tr style="cursor:default">
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${v.target}</td>
        <td>${v.type || v.scan_type || 'web'}</td>
        <td><span class="badge-severity badge-${sev}">${v.severity || 'INFO'}</span></td>
        <td>${v.title || v.name || 'Finding'}${cveLink}</td>
        <td>${v.cvss || (v.cvss_score ? v.cvss_score.toFixed(1) : '—')}</td>
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
const iocHistory = [];

async function checkIP() {
  const ip = document.getElementById('ip-check-input').value.trim();
  if (!ip) return toast('Enter an IP address', 'error');

  const result = document.getElementById('ip-check-result');
  result.innerHTML = '<div class="spinner"></div><span class="line-dim" style="margin-left:8px">Querying Shodan, VirusTotal, AbuseIPDB...</span>';

  try {
    const data = await api('/api/v1/recon/passive', {
      method: 'POST',
      body: { target: ip, modules: ['osint'] }
    });

    const sources = data?.sources || {};
    const shodan = sources?.shodan || {};
    const vt = sources?.virustotal || {};
    const risk = data?.aggregate_risk_score || 0;
    const riskPct = Math.round(risk * 100);
    const riskColor = risk > 0.7 ? 'var(--accent-red)' : risk > 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)';

    result.innerHTML = renderRiskBar(riskPct, riskColor)
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">'
      + renderShodanCard(shodan)
      + renderVTCard(vt)
      + '</div>';
    toast('IP intelligence gathered', 'success');
  } catch (e) {
    result.innerHTML = '<div class="terminal"><span class="line-error">Error: ' + e.message + '</span></div>';
    toast('IP check failed', 'error');
  }
}

// ─── OSINT Render Helpers ───────────────────
function renderRiskBar(pct, color) {
  return '<div class="card" style="margin-bottom:12px">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'
    + '<span style="font-weight:600">Aggregate Risk Score</span>'
    + '<span style="color:' + color + ';font-size:20px;font-weight:700">' + pct + '%</span>'
    + '</div>'
    + '<div style="background:rgba(255,255,255,0.1);border-radius:4px;height:8px">'
    + '<div class="risk-bar-fill" style="background:' + color + ';width:' + pct + '%;height:100%;border-radius:4px"></div>'
    + '</div></div>';
}

function renderShodanCard(shodan) {
  var html = '<div class="card">'
    + '<div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-shodan">📡 SHODAN</span></div>';
  if (shodan?.error) {
    html += '<span class="line-warning">' + shodan.error + '</span>';
  } else {
    html += '<div style="font-size:12px;line-height:2">';
    html += '<div><span style="color:var(--text-muted)">Org:</span> ' + (shodan?.org || '—') + '</div>';
    html += '<div><span style="color:var(--text-muted)">Country:</span> ' + (shodan?.country || '—') + '</div>';
    html += '<div><span style="color:var(--text-muted)">ISP:</span> ' + (shodan?.isp || '—') + '</div>';
    // Ports
    var ports = (shodan?.ports || []).slice(0, 8);
    html += '<div><span style="color:var(--text-muted)">Open Ports:</span> ';
    ports.forEach(function (p) {
      html += '<span style="background:rgba(59,130,246,0.2);color:var(--accent-blue);padding:1px 5px;border-radius:3px;font-size:10px;margin:1px">' + p + '</span>';
    });
    html += '</div>';
    // CVEs
    var vulns = (shodan?.vulns || []).slice(0, 5);
    if (vulns.length > 0) {
      html += '<div><span style="color:var(--text-muted)">CVEs:</span> ';
      vulns.forEach(function (v) {
        html += '<span style="background:rgba(239,68,68,0.2);color:var(--accent-red);padding:1px 5px;border-radius:3px;font-size:10px;margin:1px">' + v + '</span>';
      });
      html += '</div>';
    } else {
      html += '<div><span style="color:var(--text-muted)">CVEs:</span> <span style="color:var(--accent-green)">None detected</span></div>';
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}

function renderVTCard(vt) {
  var html = '<div class="card">'
    + '<div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-virustotal">🦠 VIRUSTOTAL</span></div>';
  if (vt?.error) {
    html += '<span class="line-warning">' + vt.error + '</span>';
  } else {
    var repColor = (vt?.reputation || 0) < 0 ? 'var(--accent-red)' : 'var(--accent-green)';
    html += '<div style="font-size:12px;line-height:2">';
    html += '<div><span style="color:var(--text-muted)">Reputation:</span> <span style="color:' + repColor + '">' + (vt?.reputation ?? '—') + '</span></div>';
    html += '<div style="display:flex;gap:8px;margin-top:4px">';
    html += '<span style="background:rgba(239,68,68,0.2);color:var(--accent-red);padding:3px 8px;border-radius:4px;font-size:12px">🔴 ' + (vt?.detections?.malicious ?? 0) + ' Malicious</span>';
    html += '<span style="background:rgba(251,191,36,0.2);color:var(--accent-orange);padding:3px 8px;border-radius:4px;font-size:12px">🟡 ' + (vt?.detections?.suspicious ?? 0) + ' Suspicious</span>';
    html += '</div>';
    html += '<div style="margin-top:4px"><span style="color:var(--accent-green);font-size:11px">✓ ' + (vt?.detections?.harmless ?? 0) + ' engines clean</span></div>';
    if (vt?.asn) html += '<div><span style="color:var(--text-muted)">ASN:</span> ' + vt.asn + ' (' + (vt?.as_owner || '') + ')</div>';
    if (vt?.country) html += '<div><span style="color:var(--text-muted)">Country:</span> ' + vt.country + '</div>';
    html += '</div>';
  }
  html += '</div>';
  return html;
}

async function lookupDomain() {
  const domain = document.getElementById('domain-lookup-input').value.trim();
  if (!domain) return toast('Enter a domain', 'error');

  const result = document.getElementById('domain-lookup-result');
  result.innerHTML = '<div class="spinner"></div><span class="line-dim" style="margin-left:8px">Running DNS, WHOIS, Subdomain + OSINT feeds...</span>';

  try {
    const data = await api('/api/v1/recon/passive', {
      method: 'POST',
      body: { target: domain, modules: ['dns', 'whois', 'subdomain', 'osint'] }
    });

    const dns = data?.dns || data?.results?.dns || {};
    const whois = data?.whois || data?.results?.whois || {};
    const subdomains = data?.subdomains || data?.results?.subdomains || [];
    const sources = data?.sources || {};
    const vt = sources?.virustotal || data?.results?.osint?.virustotal || {};
    const shodan = sources?.shodan || data?.results?.osint?.shodan || {};

    var html = '';

    // Header card
    var vtScoreHtml = '';
    if (vt?.reputation !== undefined) {
      var vtColor = vt.reputation < 0 ? 'var(--accent-red)' : 'var(--accent-green)';
      vtScoreHtml = '<div style="text-align:center"><div style="font-size:22px;font-weight:700;color:' + vtColor + '">' + vt.reputation + '</div><div style="font-size:10px;color:var(--text-muted)">VT Score</div></div>';
    }
    html += '<div class="card" style="margin-bottom:12px;display:flex;gap:16px;align-items:center">';
    html += '<div style="font-size:28px">🌐</div>';
    html += '<div style="flex:1"><div style="font-size:16px;font-weight:700">' + domain + '</div>';
    html += '<div style="font-size:12px;color:var(--text-muted)">';
    if (whois?.registrar) html += 'Registrar: ' + whois.registrar + ' &nbsp;|&nbsp; ';
    if (whois?.creation_date) html += 'Created: ' + whois.creation_date;
    html += '</div></div>' + vtScoreHtml + '</div>';

    // DNS + VT cards row
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">';
    html += renderDNSCard(dns);
    html += renderVTCardDomain(vt);
    html += '</div>';

    // Subdomains
    var allSubs = [...new Set([
      ...(Array.isArray(subdomains) ? subdomains : []),
      ...(shodan?.subdomains || [])
    ])];
    if (allSubs.length > 0) {
      html += '<div class="card" style="margin-bottom:12px">';
      html += '<div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-censys">🔗 SUBDOMAINS</span>';
      html += '<span style="color:var(--text-muted);font-weight:400;margin-left:6px">(' + allSubs.length + ' total)</span></div>';
      html += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
      allSubs.slice(0, 24).forEach(function (s) {
        html += '<span class="subdomain-chip">' + s + '</span>';
      });
      html += '</div></div>';
    }

    result.innerHTML = html;
    toast('Domain intelligence complete', 'success');
  } catch (e) {
    result.innerHTML = '<div class="terminal"><span class="line-error">Error: ' + e.message + '</span></div>';
    toast('Domain lookup failed', 'error');
  }
}

function renderDNSCard(dns) {
  var html = '<div class="card">';
  html += '<div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-censys">🔍 DNS RECORDS</span></div>';
  html += '<div style="font-size:12px;line-height:1.8">';
  if (dns?.a) html += '<div><span style="color:var(--text-muted)">A:</span> ' + (Array.isArray(dns.a) ? dns.a.join(', ') : dns.a) + '</div>';
  if (dns?.mx) html += '<div><span style="color:var(--text-muted)">MX:</span> ' + (Array.isArray(dns.mx) ? dns.mx.slice(0, 3).join(', ') : dns.mx) + '</div>';
  if (dns?.ns) html += '<div><span style="color:var(--text-muted)">NS:</span> ' + (Array.isArray(dns.ns) ? dns.ns.slice(0, 3).join(', ') : dns.ns) + '</div>';
  if (dns?.txt) html += '<div><span style="color:var(--text-muted)">TXT:</span> <span style="font-size:10px">' + (Array.isArray(dns.txt) ? dns.txt.slice(0, 2).join(' | ').substring(0, 120) : dns.txt) + '</span></div>';
  if (!dns?.a && !dns?.mx && !dns?.ns) html += '<span class="line-dim">No DNS data returned</span>';
  html += '</div></div>';
  return html;
}

function renderVTCardDomain(vt) {
  var html = '<div class="card">';
  html += '<div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-virustotal">🦠 VIRUSTOTAL</span></div>';
  if (vt?.error) {
    html += '<span class="line-warning">' + vt.error + '</span>';
  } else {
    html += '<div style="font-size:12px;line-height:1.8">';
    html += '<div style="display:flex;gap:8px;margin-bottom:6px">';
    html += '<span style="background:rgba(239,68,68,0.2);color:var(--accent-red);padding:2px 8px;border-radius:4px">🔴 ' + (vt?.detections?.malicious ?? 0) + ' Malicious</span>';
    html += '<span style="background:rgba(251,191,36,0.2);color:var(--accent-orange);padding:2px 8px;border-radius:4px">🟡 ' + (vt?.detections?.suspicious ?? 0) + ' Suspicious</span>';
    html += '</div>';
    if (vt?.registrar) html += '<div><span style="color:var(--text-muted)">Registrar:</span> ' + vt.registrar + '</div>';
    if (vt?.categories && Object.keys(vt.categories).length) {
      html += '<div><span style="color:var(--text-muted)">Category:</span> ' + Object.values(vt.categories).slice(0, 2).join(', ') + '</div>';
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}

// ─── IOC Tracker ────────────────────────────
async function trackIOC() {
  const input = document.getElementById('ioc-track-input');
  if (!input) return;
  const iocValue = input.value.trim();
  if (!iocValue) return toast('Enter an IOC (IP, domain, or hash)', 'error');

  const container = document.getElementById('ioc-track-result');
  if (!container) return;
  container.innerHTML = '<div class="spinner"></div>';

  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(iocValue);
  const isHash = /^[a-fA-F0-9]{32,64}$/.test(iocValue);
  const iocType = isIP ? 'ip' : isHash ? 'hash' : 'domain';

  try {
    const data = await api('/api/v1/recon/passive', {
      method: 'POST',
      body: { target: iocValue, modules: ['osint'] }
    });

    const risk = data?.aggregate_risk_score || 0;
    const riskLabel = risk > 0.7 ? 'HIGH RISK' : risk > 0.3 ? 'MEDIUM RISK' : 'LOW RISK';
    const riskColor = risk > 0.7 ? 'var(--accent-red)' : risk > 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)';

    iocHistory.unshift({ ioc: iocValue, type: iocType, risk: riskLabel, riskColor, timestamp: now(), data });

    const kpiIocs = document.getElementById('kpi-iocs');
    if (kpiIocs) kpiIocs.textContent = iocHistory.length;

    const tableBody = document.getElementById('ioc-table-body');
    if (tableBody) {
      var rows = '';
      iocHistory.slice(0, 20).forEach(function (entry) {
        rows += '<tr>';
        rows += '<td style="font-family:monospace;font-size:12px">' + entry.ioc + '</td>';
        rows += '<td><span class="source-badge source-censys">' + entry.type.toUpperCase() + '</span></td>';
        rows += '<td><span style="color:' + entry.riskColor + ';font-weight:600;font-size:12px">' + entry.risk + '</span></td>';
        rows += '<td style="color:var(--text-muted);font-size:11px">' + entry.timestamp + '</td>';
        rows += '</tr>';
      });
      tableBody.innerHTML = rows;
    }

    container.innerHTML = '<span class="line-success">✓ IOC tracked: ' + iocValue + ' — <span style="color:' + riskColor + '">' + riskLabel + '</span></span>';
    input.value = '';
    toast('IOC tracked: ' + riskLabel, risk > 0.3 ? 'error' : 'success');
  } catch (e) {
    container.innerHTML = '<span class="line-error">Error: ' + e.message + '</span>';
    toast('IOC tracking failed', 'error');
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

async function loadAIModules() {
  const list = document.getElementById('ai-modules-list');
  let modules = AI_MODULES; // default fallback

  // Try to load live module status from backend
  try {
    const data = await api('/api/v1/ai/modules');
    if (data?.modules && Array.isArray(data.modules) && data.modules.length > 0) {
      modules = data.modules;
    }
  } catch (_) { /* use hardcoded fallback */ }

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
  output.innerHTML = `< span class="line-info" > Analyzing: ${prompt}</span > <br><div class="spinner"></div>`;

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

// ─── Reports ────────────────────────────────────────────
const REPORT_TITLES = {
  executive: '📊 Executive Summary Report',
  technical: '🔧 Technical Report',
  compliance: '✅ Compliance Report',
  vulnerability: '⚠️ Vulnerability Report',
  pentest: '🗡️ Penetration Test Report',
};

function generateReport(type) {
  const card = document.getElementById('report-output');
  const title = document.getElementById('report-title');
  const content = document.getElementById('report-content');
  card.style.display = 'block';

  title.textContent = REPORT_TITLES[type] || 'Report';

  const critCount = vulnResults.filter(v => v.severity === 'CRITICAL').length;
  const highCount = vulnResults.filter(v => v.severity === 'HIGH').length;
  const medCount = vulnResults.filter(v => v.severity === 'MEDIUM').length;
  const lowCount = vulnResults.filter(v => v.severity === 'LOW').length;

  var rpt = '<span class="line-info">═══════════════════════════════════════</span><br>';
  rpt += '<span class="line-success">' + (REPORT_TITLES[type] || 'Report') + '</span><br>';
  rpt += '<span class="line-info">═══════════════════════════════════════</span><br><br>';
  rpt += '<span class="line-dim">Generated: ' + new Date().toISOString() + '</span><br>';
  rpt += '<span class="line-dim">Platform: OfSec V3 — Vector Triangulum</span><br><br>';
  rpt += '<span class="line-info">── Scan Summary ──────────────────────</span><br>';
  rpt += '<span>  Total scans run:     ' + scanHistory.length + '</span><br>';
  rpt += '<span>  Vulnerabilities:     ' + vulnResults.length + '</span><br>';
  rpt += '<span style="color:var(--accent-red)">  Critical:            ' + critCount + '</span><br>';
  rpt += '<span style="color:var(--accent-orange)">  High:                ' + highCount + '</span><br>';
  rpt += '<span style="color:#f59e0b">  Medium:              ' + medCount + '</span><br>';
  rpt += '<span style="color:var(--accent-green)">  Low:                 ' + lowCount + '</span><br><br>';
  rpt += '<span class="line-info">── Scanned Targets ───────────────────</span><br>';
  if (scanHistory.length) {
    scanHistory.forEach(function (s) {
      rpt += '<span>  • ' + s.target + ' &nbsp;[' + s.type + '] &nbsp;→ ' + s.findings + ' finding' + (s.findings !== 1 ? 's' : '') + ' &nbsp;<span style="color:var(--text-muted)">' + s.time + '</span></span><br>';
    });
  } else {
    rpt += '<span class="line-dim">  No scans performed yet</span><br>';
  }
  if (vulnResults.length > 0) {
    rpt += '<br><span class="line-info">── Top Findings ──────────────────────</span><br>';
    vulnResults.slice(0, 10).forEach(function (v) {
      var c = v.severity === 'CRITICAL' ? 'var(--accent-red)' : v.severity === 'HIGH' ? 'var(--accent-orange)' : '#f59e0b';
      rpt += '<span>  [<span style="color:' + c + '">' + (v.severity || 'INFO') + '</span>] ' + (v.title || v.name || 'Finding') + ' — ' + v.target + '</span><br>';
    });
  }
  rpt += '<br><span class="line-dim">─── End of Report ───────────────────</span>';
  content.innerHTML = rpt;
  card.dataset.reportType = type;
  toast('Report generated', 'success');
}

// ─── Export: JSON ────────────────────────────────────────
function exportReportJSON() {
  var card = document.getElementById('report-output');
  var type = card?.dataset?.reportType || 'report';
  var payload = {
    meta: { report_type: type, generated_at: new Date().toISOString(), platform: 'OfSec V3', version: '3.0.0' },
    summary: {
      total_scans: scanHistory.length, total_vulnerabilities: vulnResults.length,
      critical: vulnResults.filter(function (v) { return v.severity === 'CRITICAL' }).length,
      high: vulnResults.filter(function (v) { return v.severity === 'HIGH' }).length,
      medium: vulnResults.filter(function (v) { return v.severity === 'MEDIUM' }).length,
      low: vulnResults.filter(function (v) { return v.severity === 'LOW' }).length,
    },
    scans: scanHistory, vulnerabilities: vulnResults,
  };
  var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = 'ofsec-' + type + '-report-' + Date.now() + '.json'; a.click();
  URL.revokeObjectURL(url);
  toast('JSON report downloaded', 'success');
}

// ─── Export: HTML ────────────────────────────────────────
function exportReportHTML() {
  var card = document.getElementById('report-output');
  var type = card?.dataset?.reportType || 'report';
  var titleText = document.getElementById('report-title')?.textContent || 'OfSec Report';
  var contentHTML = document.getElementById('report-content')?.innerHTML || '';
  var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
  html += '<title>' + titleText + ' — OfSec V3</title>';
  html += '<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f1117;color:#e2e8f0;font-family:"JetBrains Mono","Courier New",monospace;font-size:13px;line-height:1.6;padding:40px}';
  html += 'header{border-bottom:1px solid #1e293b;padding-bottom:20px;margin-bottom:28px}header h1{font-size:22px;color:#38bdf8}header p{font-size:12px;color:#64748b;margin-top:4px}';
  html += '.terminal{background:#0a0e1a;border:1px solid #1e293b;border-radius:8px;padding:20px;white-space:pre-wrap;word-break:break-word}';
  html += '.line-success{color:#4ade80}.line-info{color:#38bdf8}.line-warning{color:#fb923c}.line-error{color:#f87171}.line-dim{color:#475569}';
  html += 'footer{margin-top:32px;font-size:11px;color:#334155;border-top:1px solid #1e293b;padding-top:16px}';
  html += '@media print{body{background:white;color:black}.terminal{background:#f8f8f8;border-color:#ccc}}</style></head><body>';
  html += '<header><h1>' + titleText + '</h1><p>OfSec V3 — Vector Triangulum &nbsp;|&nbsp; Generated: ' + new Date().toISOString() + '</p></header>';
  html += '<div class="terminal">' + contentHTML + '</div>';
  html += '<footer>This report was generated by OfSec V3. Confidential — for authorized use only.</footer></body></html>';
  var blob = new Blob([html], { type: 'text/html' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = 'ofsec-' + type + '-report-' + Date.now() + '.html'; a.click();
  URL.revokeObjectURL(url);
  toast('HTML report downloaded', 'success');
}

// ─── Export: via Backend API ─────────────────────────────
async function exportReportViaAPI(type) {
  toast('Generating report via API...', 'info');
  try {
    var data = await api('/api/v1/ops/reports/generate', {
      method: 'POST',
      body: { report_type: type, scan_data: { scans: scanHistory, vulnerabilities: vulnResults, generated_at: new Date().toISOString() } }
    });
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = 'ofsec-api-' + type + '-' + Date.now() + '.json'; a.click();
    URL.revokeObjectURL(url);
    toast('API report downloaded', 'success');
  } catch (e) {
    toast('API report failed: ' + e.message, 'error');
  }
}

// ─── CVE Side Panel ─────────────────────────────────────
var cvePanel = null;

function openCVEPanel(cveId) {
  if (!cvePanel) {
    cvePanel = document.createElement('div');
    cvePanel.id = 'cve-panel';
    cvePanel.style.cssText = 'position:fixed;top:0;right:-440px;width:420px;height:100vh;background:var(--bg-card);border-left:1px solid var(--border-color);z-index:1000;transition:right 0.3s cubic-bezier(0.4,0,0.2,1);overflow-y:auto;padding:24px;box-shadow:-8px 0 32px rgba(0,0,0,0.4)';
    document.body.appendChild(cvePanel);
  }
  var bd = document.getElementById('cve-backdrop');
  if (bd) bd.style.display = 'block';
  cvePanel.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">' +
    '<div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">CVE DETAIL</div>' +
    '<div style="font-family:monospace;font-size:16px;font-weight:700;color:var(--accent-blue)">' + cveId + '</div></div>' +
    '<button onclick="closeCVEPanel()" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;padding:4px">✕</button>' +
    '</div><div id="cve-panel-body"><div class="spinner"></div></div>';
  cvePanel.style.right = '0';
  fetchCVEDetail(cveId);
}

function closeCVEPanel() {
  if (cvePanel) cvePanel.style.right = '-440px';
  var bd = document.getElementById('cve-backdrop');
  if (bd) bd.style.display = 'none';
}

async function fetchCVEDetail(cveId) {
  var body = document.getElementById('cve-panel-body');
  try {
    var data = await api('/api/v1/ai/cve/analyze', { method: 'POST', body: [cveId] });
    var cve = data?.cves?.[0];
    if (!cve || !cve.found) { body.innerHTML = '<div class="terminal"><span class="line-warning">CVE not found in NVD database.</span></div>'; return; }
    var score = cve.cvss?.base_score ?? '—';
    var severity = cve.cvss?.severity ?? 'UNKNOWN';
    var sevColor = severity === 'CRITICAL' ? 'var(--accent-red)' : severity === 'HIGH' ? 'var(--accent-orange)' : severity === 'MEDIUM' ? '#f59e0b' : 'var(--accent-green)';
    var sevBg = severity === 'CRITICAL' ? '239,68,68' : severity === 'HIGH' ? '249,115,22' : '59,130,246';
    var html = '<div style="text-align:center;padding:20px;background:rgba(' + sevBg + ',0.1);border-radius:var(--radius);margin-bottom:16px;border:1px solid ' + sevColor + '40">';
    html += '<div style="font-size:48px;font-weight:900;color:' + sevColor + ';line-height:1">' + score + '</div>';
    html += '<div style="font-size:13px;font-weight:700;color:' + sevColor + ';margin-top:4px">' + severity + '</div>';
    if (cve.cvss?.vector) html += '<div style="font-size:10px;color:var(--text-muted);margin-top:6px;font-family:monospace">' + cve.cvss.vector + '</div>';
    html += '</div>';
    html += '<div style="font-size:11px;color:var(--text-muted);margin-bottom:12px">';
    if (cve.published) html += 'Published: ' + new Date(cve.published).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    if (cve.modified) html += ' &nbsp;|&nbsp; Modified: ' + new Date(cve.modified).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    html += '</div>';
    html += '<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:6px">DESCRIPTION</div>';
    html += '<div style="font-size:12px;line-height:1.7;color:var(--text-secondary)">' + (cve.description || 'No description available.') + '</div></div>';
    if (cve.weaknesses && cve.weaknesses.length > 0) {
      html += '<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:6px">WEAKNESSES (CWE)</div><div style="display:flex;flex-wrap:wrap;gap:6px">';
      cve.weaknesses.forEach(function (w) { html += '<span style="background:rgba(251,191,36,0.15);color:#fbbf24;padding:3px 8px;border-radius:4px;font-size:11px;font-family:monospace">' + w + '</span>'; });
      html += '</div></div>';
    }
    if (cve.references && cve.references.length > 0) {
      html += '<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:6px">REFERENCES</div>';
      cve.references.slice(0, 5).forEach(function (ref) {
        var short = ref.replace('https://', '').substring(0, 55) + (ref.length > 60 ? '…' : '');
        html += '<div style="margin-bottom:4px"><a href="' + ref + '" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent-blue);word-break:break-all;text-decoration:none;opacity:0.8">↗ ' + short + '</a></div>';
      });
      html += '</div>';
    }
    html += '<div style="display:flex;gap:8px;margin-top:20px;padding-top:16px;border-top:1px solid var(--border-color)">';
    html += '<a href="https://nvd.nist.gov/vuln/detail/' + cveId + '" target="_blank" rel="noopener" class="btn btn-primary" style="flex:1;text-align:center;text-decoration:none;font-size:12px">View in NVD ↗</a>';
    html += '<button class="btn" style="font-size:12px" onclick="navigator.clipboard.writeText(\'' + cveId + '\').then(function(){toast(\'Copied\',\'success\')})">Copy ID</button>';
    html += '</div>';
    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = '<div class="terminal"><span class="line-error">Error: ' + e.message + '</span></div>';
  }
}

// ─── Defense — Live Alert Polling ───────────────────────
var alertPollInterval = null;
var lastAlertCount = 0;
var lastRefreshTime = null;
var refreshTickInterval = null;

async function loadDefenseAlerts() {
  try {
    var alertsRes, corrRes;
    try { alertsRes = await api('/api/v1/defense/alerts?limit=50'); } catch (e) { alertsRes = { alerts: [] }; }
    try { corrRes = await api('/api/v1/defense/correlation/alerts?limit=20'); } catch (e) { corrRes = { alerts: [] }; }
    var alerts = alertsRes?.alerts || [];
    var corrAlerts = corrRes?.alerts || [];
    var newAlerts = alerts.length > lastAlertCount;
    renderAlertsTable(alerts, newAlerts);
    renderCorrAlertsTable(corrAlerts);
    updateIncidentKPI();
    lastAlertCount = alerts.length;
    lastRefreshTime = Date.now();
    updateRefreshLabel();
  } catch (e) { console.warn('Alert poll error:', e); }
}

function renderAlertsTable(alerts, hasNew) {
  var body = document.getElementById('alerts-body');
  if (!body) return;
  if (alerts.length === 0) {
    body.innerHTML = '<tr><td colspan="5"><div class="empty-state"><p>No alerts currently. System is monitoring.</p></div></td></tr>';
    return;
  }
  var rows = '';
  alerts.forEach(function (a, i) {
    var sev = (a.severity || 'info').toLowerCase();
    var sevColor = sev === 'critical' ? 'var(--accent-red)' : sev === 'high' ? 'var(--accent-orange)' : sev === 'medium' ? '#f59e0b' : 'var(--accent-green)';
    var isNew = hasNew && i < (alerts.length - lastAlertCount);
    var statusBg = a.status === 'open' ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)';
    var statusColor = a.status === 'open' ? 'var(--accent-red)' : 'var(--accent-green)';
    var ts = a.timestamp || a.created_at ? new Date(a.timestamp || a.created_at).toLocaleTimeString() : now();
    rows += '<tr class="' + (isNew ? 'alert-new' : '') + '" style="transition:background 0.5s">';
    rows += '<td><span style="color:' + sevColor + ';font-weight:700;font-size:12px;text-transform:uppercase">' + (a.severity || 'INFO') + '</span></td>';
    rows += '<td style="font-size:13px">' + (a.title || a.type || a.name || 'Alert') + '</td>';
    rows += '<td style="font-size:12px;color:var(--text-muted)">' + (a.source || a.rule || '—') + '</td>';
    rows += '<td><span style="font-size:11px;padding:2px 7px;border-radius:3px;background:' + statusBg + ';color:' + statusColor + '">' + (a.status || 'open') + '</span></td>';
    rows += '<td style="color:var(--text-muted);font-size:11px">' + ts + '</td>';
    rows += '</tr>';
  });
  body.innerHTML = rows;
  if (hasNew) {
    document.querySelectorAll('.alert-new').forEach(function (row) {
      row.style.background = 'rgba(239,68,68,0.15)';
      setTimeout(function () { row.style.background = ''; }, 2000);
    });
  }
}

function renderCorrAlertsTable(alerts) {
  var body = document.getElementById('correlation-alerts-body');
  if (!body || alerts.length === 0) return;
  var rows = '';
  alerts.forEach(function (a) {
    var ts = a.triggered_at ? new Date(a.triggered_at).toLocaleTimeString() : now();
    rows += '<tr>';
    rows += '<td style="font-family:monospace;font-size:11px">' + (a.rule_id || '—') + '</td>';
    rows += '<td style="font-size:12px">' + (a.rule_name || a.description || 'Correlation Match') + '</td>';
    rows += '<td style="font-size:11px;color:var(--text-muted)">' + (a.matched_events || 0) + ' events</td>';
    rows += '<td style="font-size:11px;color:var(--text-muted)">' + ts + '</td>';
    rows += '</tr>';
  });
  body.innerHTML = rows;
}

function updateRefreshLabel() {
  var label = document.getElementById('alerts-refresh-label');
  if (!label || !lastRefreshTime) return;
  if (refreshTickInterval) clearInterval(refreshTickInterval);
  refreshTickInterval = setInterval(function () {
    var secs = Math.floor((Date.now() - lastRefreshTime) / 1000);
    label.textContent = 'Last refreshed ' + secs + 's ago';
  }, 1000);
}

async function updateIncidentKPI() {
  try {
    var alertsRes = await api('/api/v1/defense/alerts?limit=100').catch(function () { return { alerts: [] }; });
    var openCount = (alertsRes?.alerts || []).filter(function (a) { return a.status === 'open'; }).length;
    var el = document.getElementById('kpi-incidents');
    if (el) { el.textContent = openCount; el.style.color = openCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)'; }
  } catch (e) { }
}

function startAlertPolling() {
  if (alertPollInterval) clearInterval(alertPollInterval);
  loadDefenseAlerts();
  alertPollInterval = setInterval(loadDefenseAlerts, 30000);
}

function stopAlertPolling() {
  if (alertPollInterval) clearInterval(alertPollInterval);
  if (refreshTickInterval) clearInterval(refreshTickInterval);
}

// ─── Settings — Live API Key Validation ─────────────────
var KEY_DEFS = [
  { name: 'Gemini AI', key: 'GEMINI_API_KEY', critical: true, testFn: testGemini },
  { name: 'Shodan', key: 'SHODAN_API_KEY', critical: false, testFn: testShodan },
  { name: 'VirusTotal', key: 'VIRUSTOTAL_API_KEY', critical: false, testFn: testVirusTotal },
  { name: 'AbuseIPDB', key: 'ABUSEIPDB_API_KEY', critical: false, testFn: testAbuseIPDB },
  { name: 'Censys', key: 'CENSYS_API_ID', critical: false, testFn: testCensys },
  { name: 'NVD', key: 'NVD_API_KEY', critical: false, testFn: testNVD },
  { name: 'AlienVault OTX', key: 'OTX_API_KEY', critical: false, testFn: null },
  { name: 'Hunter.io', key: 'HUNTER_API_KEY', critical: false, testFn: null },
];

var keyStatuses = {};

async function loadAPIKeyStatus() {
  var container = document.getElementById('api-key-status');
  if (!container) return;

  function renderKeyGrid() {
    var rows = '';
    KEY_DEFS.forEach(function (k) {
      var s = keyStatuses[k.key] || 'idle';
      var dot = s === 'ok' ? '🟢' : s === 'error' ? '🔴' : s === 'testing' ? '🟡' : s === 'untestable' ? '🟠' : '⚪';
      var label = s === 'ok' ? 'Connected' : s === 'error' ? 'Failed / Not Set' : s === 'testing' ? 'Testing...' : s === 'untestable' ? 'Not testable' : 'Untested';
      var labelColor = s === 'ok' ? 'var(--accent-green)' : s === 'error' ? 'var(--accent-red)' : s === 'testing' ? 'var(--accent-orange)' : 'var(--text-muted)';
      var canTest = k.testFn !== null;
      rows += '<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(55,65,81,0.2);border-radius:var(--radius-sm);margin-bottom:6px">';
      rows += '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:16px">' + dot + '</span><div><div style="font-size:13px;font-weight:500">' + k.name + '</div><div style="font-size:11px;color:var(--text-muted)">' + k.key + '</div></div></div>';
      rows += '<div style="display:flex;align-items:center;gap:10px"><span style="font-size:11px;color:' + labelColor + '">' + label + '</span>';
      if (canTest) {
        rows += '<button class="btn" style="padding:3px 10px;font-size:11px" onclick="testKey(\'' + k.key + '\')"' + (s === 'testing' ? ' disabled' : '') + '>' + (s === 'testing' ? '...' : 'Test') + '</button>';
      }
      rows += '</div></div>';
    });
    container.innerHTML = rows;
  }

  renderKeyGrid();

  // Auto-test all testable keys
  KEY_DEFS.forEach(function (k) {
    if (k.testFn) {
      testKey(k.key);
    } else {
      keyStatuses[k.key] = 'untestable';
    }
  });
  renderKeyGrid();
}

async function testKey(keyName) {
  var def = KEY_DEFS.find(function (k) { return k.key === keyName; });
  if (!def || !def.testFn) return;
  keyStatuses[keyName] = 'testing';
  loadAPIKeyStatus();
  try {
    var result = await def.testFn();
    keyStatuses[keyName] = result ? 'ok' : 'error';
  } catch (e) {
    keyStatuses[keyName] = 'error';
  }
  var container = document.getElementById('api-key-status');
  if (container) {
    var rows = '';
    KEY_DEFS.forEach(function (k) {
      var s = keyStatuses[k.key] || 'idle';
      var dot = s === 'ok' ? '🟢' : s === 'error' ? '🔴' : s === 'testing' ? '🟡' : s === 'untestable' ? '🟠' : '⚪';
      var label = s === 'ok' ? 'Connected' : s === 'error' ? 'Failed / Not Set' : s === 'testing' ? 'Testing...' : s === 'untestable' ? 'Not testable' : 'Untested';
      var labelColor = s === 'ok' ? 'var(--accent-green)' : s === 'error' ? 'var(--accent-red)' : s === 'testing' ? 'var(--accent-orange)' : 'var(--text-muted)';
      var canTest = k.testFn !== null;
      rows += '<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(55,65,81,0.2);border-radius:var(--radius-sm);margin-bottom:6px">';
      rows += '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:16px">' + dot + '</span><div><div style="font-size:13px;font-weight:500">' + k.name + '</div><div style="font-size:11px;color:var(--text-muted)">' + k.key + '</div></div></div>';
      rows += '<div style="display:flex;align-items:center;gap:10px"><span style="font-size:11px;color:' + labelColor + '">' + label + '</span>';
      if (canTest) {
        rows += '<button class="btn" style="padding:3px 10px;font-size:11px" onclick="testKey(\'' + k.key + '\')"' + (s === 'testing' ? ' disabled' : '') + '>' + (s === 'testing' ? '...' : 'Test') + '</button>';
      }
      rows += '</div></div>';
    });
    container.innerHTML = rows;
  }
}

// ─── Key probe functions ─────────────────────────────────
async function testGemini() {
  try {
    var r = await api('/api/v1/ai/analyze/instant', { method: 'POST', body: { target: 'test', findings: [], analysis_type: 'general' } });
    return !r?.error?.toLowerCase().includes('api key');
  } catch (e) { return false; }
}

async function testShodan() {
  try {
    var r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return !r?.sources?.shodan?.error;
  } catch (e) { return false; }
}

async function testVirusTotal() {
  try {
    var r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return !r?.sources?.virustotal?.error;
  } catch (e) { return false; }
}

async function testAbuseIPDB() {
  try {
    var r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return r?.sources?.abuseipdb !== undefined && !r?.sources?.abuseipdb?.error;
  } catch (e) { return false; }
}

async function testCensys() {
  try {
    var r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } });
    return r?.sources?.censys !== undefined && !r?.sources?.censys?.error;
  } catch (e) { return false; }
}

async function testNVD() {
  try {
    var r = await api('/api/v1/ai/cve/analyze', { method: 'POST', body: ['CVE-2021-44228'] });
    return Array.isArray(r?.cves) && r.cves.length > 0;
  } catch (e) { return false; }
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

// ─── Data Persistence (Phase 3) ───────────────────
async function loadPersistedData() {
  try {
    // Load scan history from DB
    const scansRes = await api('/api/v1/recon/results?limit=50');
    const vulnRes = await api('/api/v1/scanner/vulnerabilities?limit=100');

    if (scansRes?.items?.length > 0) {
      scansRes.items.forEach(s => {
        if (!scanHistory.find(h => h.id === s.id)) {
          scanHistory.push({
            id: s.id,
            target: s.target,
            type: s.scan_type || 'recon',
            status: s.status,
            findings: s.result_summary?.findings_count || 0,
            time: s.started_at ? new Date(s.started_at).toLocaleTimeString() : '—',
            data: s.result_summary,
          });
        }
      });
    }

    if (vulnRes?.items?.length > 0) {
      vulnRes.items.forEach(v => {
        if (!vulnResults.find(r => r.id === v.id)) {
          vulnResults.push({
            id: v.id,
            target: v.url || 'unknown',
            severity: v.severity,
            title: v.title,
            cvss: v.cvss,
            found: v.discovered_at ? new Date(v.discovered_at).toLocaleTimeString() : '—',
          });
        }
      });
    }

    // Load IOC history
    const iocRes = await api('/api/v1/defense/ioc/history?limit=50').catch(() => null);
    if (iocRes?.items?.length > 0) {
      iocRes.items.forEach(i => {
        if (!iocHistory.find(h => h.ioc === i.value)) {
          iocHistory.push({
            ioc: i.value,
            type: i.ioc_type,
            risk: i.confidence > 0.7 ? 'HIGH RISK' : i.confidence > 0.3 ? 'MEDIUM RISK' : 'LOW RISK',
            riskColor: i.confidence > 0.7 ? 'var(--accent-red)' : i.confidence > 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)',
            timestamp: i.last_seen ? new Date(i.last_seen).toLocaleTimeString() : '—',
          });
        }
      });
    }

    updateDashboardKPIs();
    updateResults();
    toast(`Loaded ${scanHistory.length} scans, ${vulnResults.length} findings from DB`, 'info');
  } catch (e) {
    console.warn('Could not load persisted data:', e.message);
  }
}

function updateDashboardKPIs() {
  const critCount = vulnResults.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length;
  const kpiScans = document.getElementById('kpi-scans');
  if (kpiScans) kpiScans.textContent = scanHistory.length;
  const kpiVulns = document.getElementById('kpi-vulns');
  if (kpiVulns) kpiVulns.textContent = vulnResults.length;
  const kpiCrit = document.getElementById('kpi-critical');
  if (kpiCrit) {
    kpiCrit.textContent = critCount;
    kpiCrit.style.color = critCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)';
  }
}

// ─── Scan Queue ─────────────────────────────────────────────────────
let queuePollInterval = null;

async function submitScanQueue() {
  const raw = document.getElementById('queue-targets')?.value?.trim();
  if (!raw) return toast('Enter at least one target', 'error');

  const targets = raw.split('\n')
    .map(t => t.trim())
    .filter(t => t.length > 0);

  if (targets.length === 0) return toast('No valid targets found', 'error');
  if (targets.length > 50) return toast('Maximum 50 targets per batch', 'error');

  const scanType = document.getElementById('queue-scan-type')?.value || 'recon';
  const priority = document.getElementById('queue-priority')?.value || 'normal';

  toast(`Submitting ${targets.length} target(s)...`, 'info');

  try {
    const data = await api('/api/v1/ops/queue/submit', {
      method: 'POST',
      body: { targets, scan_type: scanType, priority }
    });

    toast(`${data.submitted} scan(s) queued`, 'success');
    document.getElementById('queue-targets').value = '';
    loadQueueStatus();

    // Auto-poll while jobs are running
    startQueuePolling();
  } catch (e) {
    toast('Queue submission failed: ' + e.message, 'error');
  }
}

async function loadQueueStatus() {
  try {
    const data = await api('/api/v1/ops/queue/status');
    const jobs = data.jobs || [];
    const counts = data.status_counts || {};

    // Update summary line
    const summary = document.getElementById('queue-summary');
    if (summary) {
      const runningCount = counts.running || counts.active || 0;
      const doneCount = counts.completed || 0;
      summary.textContent = jobs.length === 0
        ? 'Queue is empty'
        : `${jobs.length} job${jobs.length !== 1 ? 's' : ''} -- ${runningCount} running, ${doneCount} completed`;
    }

    // Render table
    const tbody = document.getElementById('queue-table-body');
    if (!tbody) return;

    if (jobs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px">No jobs in queue</td></tr>`;
      stopQueuePolling();
      return;
    }

    tbody.innerHTML = jobs.map(job => {
      const cfg = job.config || {};
      const jobStatus = job.status || 'active';
      const statusColor = jobStatus === 'completed' ? 'var(--accent-green)'
        : jobStatus === 'failed' ? 'var(--accent-red)'
          : jobStatus === 'running' ? 'var(--accent-orange)'
            : 'var(--text-muted)';
      const statusIcon = jobStatus === 'completed' ? 'V'
        : jobStatus === 'failed' ? 'X'
          : jobStatus === 'running' ? 'o'
            : '-';
      return `
        <tr>
          <td style="font-family:'JetBrains Mono',monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis">
            ${job.target || cfg.target || '--'}
          </td>
          <td style="font-size:11px">
            <span style="background:rgba(59,130,246,0.15);color:var(--accent-blue);
                         padding:1px 6px;border-radius:3px">
              ${(cfg.scan_type || 'recon').toUpperCase()}
            </span>
          </td>
          <td>
            <span style="color:${statusColor};font-size:12px;font-weight:600">
              ${statusIcon} ${jobStatus}
            </span>
          </td>
          <td style="font-size:11px;color:var(--text-muted)">
            ${job.created_at ? new Date(job.created_at).toLocaleTimeString() : '--'}
          </td>
          <td>
            ${jobStatus !== 'completed' ? `
              <button onclick="cancelQueueJob('${job.id}')"
                style="background:none;border:none;color:var(--accent-red);cursor:pointer;font-size:11px;padding:2px 6px">
                X
              </button>` : ''
        }
          </td>
        </tr>
      `;
    }).join('');

  } catch (e) {
    console.warn('Queue status error:', e.message);
  }
}

async function cancelQueueJob(jobId) {
  try {
    await api(`/api/v1/ops/queue/${jobId}/cancel`, { method: 'POST' });
    toast('Job cancelled', 'info');
    loadQueueStatus();
  } catch (e) {
    toast('Cancel failed: ' + e.message, 'error');
  }
}

function startQueuePolling() {
  if (queuePollInterval) return; // already polling
  queuePollInterval = setInterval(loadQueueStatus, 10_000);
}

function stopQueuePolling() {
  if (queuePollInterval) {
    clearInterval(queuePollInterval);
    queuePollInterval = null;
  }
}


// ─── Schedule Management ────────────────────────────────

async function loadSchedules() {
  const el = document.getElementById('schedule-list');
  if (!el) return;
  try {
    const data = await api('/api/v1/ops/schedules');
    const jobs = data.schedules || [];
    if (jobs.length === 0) {
      el.innerHTML = '<span style="color:var(--text-dim)">No scheduled scans</span>';
      return;
    }
    el.innerHTML = jobs.map(j => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;
        border-bottom:1px solid var(--border-color)">
        <div>
          <strong>${j.kwargs?.target || j.job_id}</strong>
          <span style="color:var(--text-dim);margin-left:8px">${j.status}</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <span style="font-size:11px;color:var(--text-dim)">
            Next: ${j.next_run ? new Date(j.next_run).toLocaleString() : 'N/A'}
          </span>
          <button class="btn btn-secondary" style="font-size:11px;padding:2px 8px"
            onclick="deleteSchedule('${j.job_id}')">✕</button>
        </div>
      </div>
    `).join('');
  } catch (e) {
    el.innerHTML = `<span style="color:var(--accent-red)">${e.message}</span>`;
  }
}

async function createSchedule() {
  const target = document.getElementById('sched-target')?.value?.trim();
  const cron = document.getElementById('sched-cron')?.value?.trim() || '0 2 * * *';
  if (!target) return toast('Target required', 'warning');

  try {
    await api('/api/v1/ops/schedules', {
      method: 'POST',
      body: {
        target,
        scan_type: 'recon',
        schedule_type: 'cron',
        schedule_value: cron,
      },
    });
    toast('Schedule created', 'success');
    document.getElementById('sched-target').value = '';
    document.getElementById('sched-cron').value = '';
    loadSchedules();
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  }
}

async function deleteSchedule(jobId) {
  try {
    await api(`/api/v1/ops/schedules/${jobId}`, { method: 'DELETE' });
    toast('Schedule removed', 'success');
    loadSchedules();
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  }
}


// ─── Account Management ────────────────────────────────

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


// ─── Threat Intel Sweep ───────────────────────────────────────────────
async function runIntelSweep() {
  const btn = document.getElementById('btn-intel-sweep');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Sweeping...'; }

  try {
    const data = await api('/api/v1/defense/intel/sweep', { method: 'POST' });
    toast('IOC sweep started — results will appear in IOC History shortly', 'success');

    // Poll for new IOCs after a short delay
    setTimeout(async () => {
      await loadIOCHistory?.();
      if (btn) { btn.disabled = false; btn.textContent = '🔄 Run Sweep Now'; }
    }, 8000);
  } catch (e) {
    toast('Sweep failed: ' + e.message, 'error');
    if (btn) { btn.disabled = false; btn.textContent = '🔄 Run Sweep Now'; }
  }
}

async function loadIntelSweepStatus() {
  try {
    const data = await api('/api/v1/defense/intel/sweep/status');
    const el = document.getElementById('intel-sweep-status');
    if (!el) return;
    const next = data.next_run
      ? new Date(data.next_run).toLocaleString() : 'unknown';
    el.textContent = `Auto-sweep: daily at 03:00 UTC · Next: ${next}`;
  } catch (_) { }
}


// ─── Notification Config ──────────────────────────────────────────────
async function loadNotifConfig() {
  const el = document.getElementById('notif-config-display');
  if (!el) return;
  try {
    const cfg = await api('/api/v1/ops/notifications/config');

    const row = (label, value, ok) => `
      <div style="display:flex;justify-content:space-between;align-items:center;
                  padding:6px 0;border-bottom:1px solid rgba(55,65,81,0.3)">
        <span style="font-size:12px;color:var(--text-secondary)">${label}</span>
        <span style="font-size:12px;color:${ok ? 'var(--accent-green)' : 'var(--text-muted)'}">
          ${ok ? '● ' : '○ '}${value}
        </span>
      </div>`;

    el.innerHTML = `
      ${row('Email',
      cfg.email.enabled ? `${cfg.email.to || 'no recipient'}` : 'Disabled',
      cfg.email.enabled && cfg.email.configured)}
      ${row('Webhook',
        cfg.webhook.enabled
          ? (cfg.webhook.url_configured ? cfg.webhook.url_preview : 'no URL')
          : 'Disabled',
        cfg.webhook.enabled && cfg.webhook.url_configured)}
      ${row('Webhook 2',
          cfg.webhook.url_2_configured ? 'Configured' : 'Not set',
          cfg.webhook.url_2_configured)}
    `;
  } catch (e) {
    el.innerHTML = `<span style="color:var(--accent-red);font-size:13px">
      Could not load config</span>`;
  }
}

async function sendTestAlert() {
  try {
    const data = await api('/api/v1/ops/notifications/test', { method: 'POST' });
    if (data.status === 'no_channels') {
      toast('No channels configured — set ALERT_EMAIL_ENABLED or ALERT_WEBHOOK_ENABLED in .env', 'warning');
    } else {
      toast(`Test alert sent to: ${data.channels.join(', ')}`, 'success');
    }
  } catch (e) {
    toast('Test failed: ' + e.message, 'error');
  }
}

// ─── Dead-Letter Queue ────────────────────────────────────────────────
async function loadDLQ() {
  const el = document.getElementById('dlq-display');
  const btnRetry = document.getElementById('btn-retry-dlq');

  // Try to find or create nav badge
  let navBadge = document.getElementById('settings-dlq-badge');
  if (!navBadge) {
    const settingsNavItem = document.querySelector('.nav-item[data-page="settings"]');
    if (settingsNavItem) {
      navBadge = document.createElement('span');
      navBadge.id = 'settings-dlq-badge';
      navBadge.className = 'nav-badge';
      navBadge.style.backgroundColor = 'var(--accent-red)';
      navBadge.style.display = 'none';
      settingsNavItem.appendChild(navBadge);
    }
  }

  try {
    const data = await api('/api/v1/ops/notifications/failed');

    // Update nav badge
    if (navBadge) {
      if (data.count > 0) {
        navBadge.textContent = data.count > 99 ? '99+' : data.count;
        navBadge.style.display = 'inline-flex';
      } else {
        navBadge.style.display = 'none';
      }
    }

    if (!el) return;

    if (!data.failed || data.failed.length === 0) {
      el.innerHTML = '<span style="color:var(--text-dim)">DLQ is empty. All webhooks are sending successfully.</span>';
      if (btnRetry) btnRetry.style.display = 'none';
      return;
    }

    if (btnRetry) btnRetry.style.display = 'inline-block';

    const count = data.count;
    let html = `<div style="margin-bottom:12px;color:var(--accent-orange);font-weight:600">
                  ⚠️ ${count} webhook${count !== 1 ? 's' : ''} in queue
                </div>`;

    html += `<div style="max-height:200px;overflow-y:auto;border:1px solid rgba(55,65,81,0.5);border-radius:4px">
              <table style="width:100%;font-size:11px;border-collapse:collapse">
                <thead style="background:rgba(0,0,0,0.2)">
                  <tr>
                    <th style="padding:6px;text-align:left">ID</th>
                    <th style="padding:6px;text-align:left">Target</th>
                  </tr>
                </thead>
                <tbody>`;

    data.failed.forEach(item => {
      html += `<tr style="border-bottom:1px solid rgba(55,65,81,0.3)">
                <td style="padding:6px;font-family:monospace;color:var(--text-muted)">${item.id}</td>
                <td style="padding:6px;color:var(--text-secondary);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.target_url}</td>
               </tr>`;
    });

    html += `</tbody></table></div>`;
    el.innerHTML = html;

  } catch (e) {
    if (el) el.innerHTML = `<span style="color:var(--accent-red)">Could not load DLQ: ${e.message}</span>`;
  }
}

async function retryDLQ() {
  const btnRetry = document.getElementById('btn-retry-dlq');
  if (btnRetry) {
    btnRetry.disabled = true;
    btnRetry.textContent = '⏳ Retrying...';
  }

  try {
    const data = await api('/api/v1/ops/notifications/retry', { method: 'POST' });
    toast(data.message, data.still_failing === 0 ? 'success' : 'warning');
    await loadDLQ();
  } catch (e) {
    toast('Retry failed: ' + e.message, 'error');
  } finally {
    if (btnRetry) {
      btnRetry.disabled = false;
      btnRetry.textContent = '▶ Retry All';
    }
  }
}

// ─── Initialize Event Listeners ─────────────
function initEventListeners() {
  const bind = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };

  bind('login-form', 'submit', async (e) => {
    e.preventDefault();
    API_KEY = document.getElementById('login-apikey').value.trim();
    if (!API_KEY) return toast('Please enter an API key', 'error');
  
    try {
      const r = await api('/api/v1/status');
      if (r.status === 'operational') {
        document.getElementById('login-page').style.display = 'none';
        document.getElementById('app-layout').style.display = 'flex';
        toast('Welcome to OfSec V3', 'success');
  
        const hashPage = location.hash.replace('#', '');
        const validPages = ['dashboard', 'scan', 'results', 'threats', 'ai', 'defense', 'reports', 'settings'];
        navigate(validPages.includes(hashPage) ? hashPage : 'dashboard');
  
        loadDashboard();
        loadPersistedData();
        loadModuleGrid();
        loadAIModules();
        loadAPIKeyStatus();
        loadPlatformInfo();
        loadDLQ();
  
        setInterval(() => {
          loadDLQ();
        }, 30000); // Check DLQ every 30 seconds
      }
    } catch (err) {
      toast('Authentication failed: ' + err.message, 'error');
    }
  });

  bind('launch-scan-btn', 'click', launchScan);
  bind('btn-refresh-queue', 'click', loadQueueStatus);
  bind('btn-submit-queue', 'click', submitScanQueue);
  bind('btn-refresh-results', 'click', refreshResults);
  bind('btn-check-ip', 'click', checkIP);
  bind('btn-lookup-domain', 'click', lookupDomain);
  bind('btn-track-ioc', 'click', trackIOC);
  bind('btn-ask-ai', 'click', askAI);
  bind('btn-refresh-alerts', 'click', loadDefenseAlerts);
  bind('btn-export-json', 'click', exportReportJSON);
  bind('btn-export-html', 'click', exportReportHTML);
  bind('btn-retest-keys', 'click', loadAPIKeyStatus); 
  bind('btn-refresh-schedules', 'click', loadSchedules);
  bind('btn-create-schedule', 'click', createSchedule);
  bind('btn-change-password', 'click', changePassword);
  bind('btn-intel-sweep', 'click', runIntelSweep);
  bind('btn-refresh-notif', 'click', loadNotifConfig);
  bind('btn-test-alert', 'click', sendTestAlert);
  bind('btn-refresh-dlq', 'click', loadDLQ);
  bind('btn-retry-dlq', 'click', retryDLQ);

  const exportApiBtn = document.querySelector('[data-export-api="true"]');
  if (exportApiBtn) exportApiBtn.addEventListener('click', () => exportReportViaAPI('json'));
}

document.addEventListener('DOMContentLoaded', initEventListeners);


// ─── Initialize Event Listeners ─────────────
function initEventListeners() {
  const bind = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };

  bind('login-form', 'submit', async (e) => {
    e.preventDefault();
    API_KEY = document.getElementById('login-apikey').value.trim();
    if (!API_KEY) return toast('Please enter an API key', 'error');
  
    try {
      const r = await api('/api/v1/status');
      if (r.status === 'operational') {
        document.getElementById('login-page').style.display = 'none';
        document.getElementById('app-layout').style.display = 'flex';
        toast('Welcome to OfSec V3', 'success');
  
        const hashPage = location.hash.replace('#', '');
        const validPages = ['dashboard', 'scan', 'results', 'threats', 'ai', 'defense', 'reports', 'settings'];
        navigate(validPages.includes(hashPage) ? hashPage : 'dashboard');
  
        loadDashboard();
        loadPersistedData();
        loadModuleGrid();
        loadAIModules();
        loadAPIKeyStatus();
        loadPlatformInfo();
        loadDLQ();
  
        setInterval(() => {
          loadDLQ();
        }, 30000);
      }
    } catch (err) {
      toast('Authentication failed: ' + err.message, 'error');
    }
  });

  bind('launch-scan-btn', 'click', launchScan);
  bind('btn-refresh-queue', 'click', loadQueueStatus);
  bind('btn-submit-queue', 'click', submitScanQueue);
  bind('btn-refresh-results', 'click', refreshResults);
  bind('btn-check-ip', 'click', checkIP);
  bind('btn-lookup-domain', 'click', lookupDomain);
  bind('btn-track-ioc', 'click', trackIOC);
  bind('btn-ask-ai', 'click', askAI);
  bind('btn-refresh-alerts', 'click', loadDefenseAlerts);
  bind('btn-export-json', 'click', exportReportJSON);
  bind('btn-export-html', 'click', exportReportHTML);
  bind('btn-retest-keys', 'click', loadAPIKeyStatus); 
  bind('btn-refresh-schedules', 'click', loadSchedules);
  bind('btn-create-schedule', 'click', createSchedule);
  bind('btn-change-password', 'click', changePassword);
  bind('btn-intel-sweep', 'click', runIntelSweep);
  bind('btn-refresh-notif', 'click', loadNotifConfig);
  bind('btn-test-alert', 'click', sendTestAlert);
  bind('btn-refresh-dlq', 'click', loadDLQ);
  bind('btn-retry-dlq', 'click', retryDLQ);

  const exportApiBtn = document.querySelector('[data-export-api="true"]');
  if (exportApiBtn) exportApiBtn.addEventListener('click', () => exportReportViaAPI('json'));
}

document.addEventListener('DOMContentLoaded', initEventListeners);

// ─── Initialize Event Listeners ─────────────
function initEventListeners() {
  const bind = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };

  bind('launch-scan-btn', 'click', launchScan);
  bind('btn-refresh-queue', 'click', loadQueueStatus);
  bind('btn-submit-queue', 'click', submitScanQueue);
  bind('btn-refresh-results', 'click', refreshResults);
  bind('btn-check-ip', 'click', checkIP);
  bind('btn-lookup-domain', 'click', lookupDomain);
  bind('btn-track-ioc', 'click', trackIOC);
  bind('btn-ask-ai', 'click', askAI);
  bind('btn-refresh-alerts', 'click', loadDefenseAlerts);
  bind('btn-export-json', 'click', exportReportJSON);
  bind('btn-export-html', 'click', exportReportHTML);
  
  const exportApiBtn = document.querySelector('[data-export-api="true"]');
  if (exportApiBtn) exportApiBtn.addEventListener('click', () => exportReportViaAPI('pdf'));
  
  bind('btn-retest-keys', 'click', loadAPIKeyStatus); 
  bind('btn-refresh-schedules', 'click', loadSchedules);
  bind('btn-create-schedule', 'click', createSchedule);
  bind('btn-change-password', 'click', changePassword);
  bind('btn-intel-sweep', 'click', runIntelSweep);
  bind('btn-refresh-notif', 'click', loadNotifConfig);
  bind('btn-test-alert', 'click', sendTestAlert);
  bind('btn-refresh-dlq', 'click', loadDLQ);
  bind('btn-retry-dlq', 'click', retryDLQ);
}

document.addEventListener('DOMContentLoaded', initEventListeners);


// ─── Initialize Event Listeners ─────────────
function initEventListeners() {
  const bind = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };

  bind('launch-scan-btn', 'click', launchScan);
  bind('btn-refresh-queue', 'click', loadQueueStatus);
  bind('btn-submit-queue', 'click', submitScanQueue);
  bind('btn-refresh-results', 'click', refreshResults);
  bind('btn-check-ip', 'click', checkIP);
  bind('btn-lookup-domain', 'click', lookupDomain);
  bind('btn-track-ioc', 'click', trackIOC);
  bind('btn-ask-ai', 'click', askAI);
  bind('btn-refresh-alerts', 'click', loadDefenseAlerts);
  bind('btn-export-json', 'click', exportReportJSON);
  bind('btn-export-html', 'click', exportReportHTML);
  
  const exportApiBtn = document.querySelector('[data-export-api="true"]');
  if (exportApiBtn) exportApiBtn.addEventListener('click', () => exportReportViaAPI('pdf'));
  
  bind('btn-retest-keys', 'click', loadAPIKeyStatus); 
  bind('btn-refresh-schedules', 'click', loadSchedules);
  bind('btn-create-schedule', 'click', createSchedule);
  bind('btn-change-password', 'click', changePassword);
  bind('btn-intel-sweep', 'click', runIntelSweep);
  bind('btn-refresh-notif', 'click', loadNotifConfig);
  bind('btn-test-alert', 'click', sendTestAlert);
  bind('btn-refresh-dlq', 'click', loadDLQ);
  bind('btn-retry-dlq', 'click', retryDLQ);
}

document.addEventListener('DOMContentLoaded', initEventListeners);

// --- Initialize Event Listeners -------------
function initEventListeners() {
  const bind = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };
  bind('login-form', 'submit', async (e) => { e.preventDefault(); API_KEY = document.getElementById('login-apikey').value.trim(); if (!API_KEY) return toast('Please enter an API key', 'error'); try { const r = await api('/api/v1/status'); if (r.status === 'operational') { document.getElementById('login-page').style.display = 'none'; document.getElementById('app-layout').style.display = 'flex'; toast('Welcome to OfSec V3', 'success'); const hashPage = location.hash.replace('#', ''); const validPages = ['dashboard', 'scan', 'results', 'threats', 'ai', 'defense', 'reports', 'settings']; navigate(validPages.includes(hashPage) ? hashPage : 'dashboard'); loadDashboard(); loadPersistedData(); loadModuleGrid(); loadAIModules(); loadAPIKeyStatus(); loadPlatformInfo(); loadDLQ(); setInterval(() => { loadDLQ(); }, 30000); } } catch (err) { toast('Authentication failed: ' + err.message, 'error'); } });
  bind('launch-scan-btn', 'click', launchScan);
  bind('btn-refresh-queue', 'click', loadQueueStatus);
  bind('btn-submit-queue', 'click', submitScanQueue);
  bind('btn-refresh-results', 'click', refreshResults);
  bind('btn-check-ip', 'click', checkIP);
  bind('btn-lookup-domain', 'click', lookupDomain);
  bind('btn-track-ioc', 'click', trackIOC);
  bind('btn-ask-ai', 'click', askAI);
  bind('btn-refresh-alerts', 'click', loadDefenseAlerts);
  bind('btn-export-json', 'click', exportReportJSON);
  bind('btn-export-html', 'click', exportReportHTML);
  bind('btn-retest-keys', 'click', loadAPIKeyStatus);
  bind('btn-refresh-schedules', 'click', loadSchedules);
  bind('btn-create-schedule', 'click', createSchedule);
  bind('btn-change-password', 'click', changePassword);
  bind('btn-intel-sweep', 'click', runIntelSweep);
  bind('btn-refresh-notif', 'click', loadNotifConfig);
  bind('btn-test-alert', 'click', sendTestAlert);
  bind('btn-refresh-dlq', 'click', loadDLQ);
  bind('btn-retry-dlq', 'click', retryDLQ);
  const exportApiBtn = document.querySelector('[data-export-api= true]');
  if (exportApiBtn) exportApiBtn.addEventListener('click', () => exportReportViaAPI('json'));
}
document.addEventListener('DOMContentLoaded', initEventListeners);
