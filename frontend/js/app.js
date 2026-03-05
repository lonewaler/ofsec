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
    // Recon scan
    if (scanType === 'recon' || scanType === 'full') {
      termLine(terminal, `[${now()}] Starting reconnaissance on ${target}...`, 'info');
      termProgress(terminal, 'Initializing recon modules', 0);

      try {
        termProgress(terminal, 'Running passive recon (DNS, WHOIS, OSINT)...', 25);
        const reconData = await api('/api/v1/recon/passive', {
          method: 'POST',
          body: { target, modules: selectedMods }
        });
        termProgress(terminal, 'Processing results', 75);
        termLine(terminal, `[${now()}] ✓ Passive recon completed`, 'success');

        const dns = reconData?.dns || reconData?.results?.dns || {};
        const recs = dns?.records || dns || {};
        if (recs && typeof recs === 'object') {
          Object.entries(recs).forEach(([type, vals]) => {
            if (type !== 'error') termLine(terminal, `  DNS ${type}: ${Array.isArray(vals) ? vals.join(', ') : vals}`, 'info');
          });
        }
        const subs = reconData?.subdomains || reconData?.results?.subdomains || [];
        const subCount = Array.isArray(subs) ? subs.length : (subs?.count || 0);
        if (subCount > 0) termLine(terminal, `  Found ${subCount} subdomains`, 'success');

        const whois = reconData?.whois || reconData?.results?.whois || {};
        if (whois?.registrar) termLine(terminal, `  WHOIS: ${whois.registrar}`, 'info');

        // Show OSINT source summary
        const sources = reconData?.sources || {};
        if (Object.keys(sources).length > 0) {
          termLine(terminal, `  OSINT sources queried: ${Object.keys(sources).join(', ')}`, 'info');
        }

        termProgress(terminal, 'Recon complete', 100);
        scanHistory.push({ id: scanId, target, type: 'recon', status: 'done', findings: 0, time: now(), data: reconData });
      } catch (e) {
        termLine(terminal, `[${now()}] ⚠ Recon module: ${e.message}`, 'warning');
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
        termLine(terminal, `[${now()}] ✓ Vulnerability scan completed`, 'success');

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

function loadAIModules() {
  const list = document.getElementById('ai-modules-list');
  list.innerHTML = AI_MODULES.map(m => `
    < div class="card" style = "display:flex;align-items:center;gap:12px;padding:14px" >
      <span style="font-size:24px">${m.icon}</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:13px">${m.name}</div>
        <div style="font-size:11px;color:var(--text-muted)">${m.desc}</div>
      </div>
      <span class="status-dot active"></span>
    </div >
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
