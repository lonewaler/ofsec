/**
 * OfSec V3 — Scan Page Module
 */
import { api, getApiKey } from '../api.js';
import { toast, termLine, termProgress, now } from '../ui.js';
import { onPageEnter } from '../router.js';
import { state } from '../main.js';

// ─── Module Definitions ────────────────────────
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

export function loadModuleGrid() {
    const grid = document.getElementById('module-grid');
    if (!grid) return;
    grid.innerHTML = MODULES.map(m => `
    <div class="module-chip ${m.selected ? 'selected' : ''}" data-module-id="${m.id}">
      <span>${m.icon}</span> ${m.name}
    </div>
  `).join('');
    grid.addEventListener('click', (e) => {
        const chip = e.target.closest('.module-chip');
        if (!chip) return;
        const mod = MODULES.find(m => m.id === chip.dataset.moduleId);
        if (mod) {
            mod.selected = !mod.selected;
            chip.classList.toggle('selected');
        }
    });
}

// ─── Vulnerability Summary ─────────────────────
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

// ─── Launch Scan ────────────────────────────────
export async function launchScan() {
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
        if (scanType === 'recon' || scanType === 'full') {
            termLine(terminal, `[${now()}] Starting reconnaissance on ${target}...`, 'info');
            try {
                const initRes = await api('/api/v1/recon/passive?stream=true', {
                    method: 'POST', body: { target, modules: selectedMods }
                });
                const dbScanId = initRes.scan_id;
                termLine(terminal, `[${now()}] Scan started (ID: ${dbScanId}) -- streaming results...`, 'success');
                await streamScanResults(dbScanId, terminal, target);
            } catch (e) {
                termLine(terminal, `[${now()}] SSE not available, falling back...`, 'warning');
                try {
                    const reconData = await api('/api/v1/recon/passive', {
                        method: 'POST', body: { target, modules: selectedMods }
                    });
                    termLine(terminal, `[${now()}] Passive recon completed`, 'success');
                    const dns = reconData?.dns || reconData?.results?.dns || {};
                    const recs = dns?.records || dns || {};
                    if (recs && typeof recs === 'object') {
                        Object.entries(recs).forEach(([type, vals]) => {
                            if (type !== 'error') termLine(terminal, `  DNS ${type}: ${Array.isArray(vals) ? vals.join(', ') : vals}`, 'info');
                        });
                    }
                    state.scanHistory.push({ id: scanId, target, type: 'recon', status: 'done', findings: 0, time: now(), data: reconData });
                } catch (err) {
                    termLine(terminal, `[${now()}] Recon module: ${err.message}`, 'warning');
                }
            }
        }

        if (scanType === 'vuln' || scanType === 'full') {
            termLine(terminal, `[${now()}] Starting vulnerability scan on ${target}...`, 'info');
            termProgress(terminal, 'Initializing scanner', 0);
            try {
                termProgress(terminal, 'Scanning web, SSL, headers...', 25);
                const vulnData = await api('/api/v1/scanner/scan', {
                    method: 'POST', body: { target, scan_types: ['web', 'ssl', 'headers'] }
                });
                termProgress(terminal, 'Analyzing findings', 75);
                termLine(terminal, `[${now()}] Vulnerability scan completed`, 'success');
                const findings = vulnData?.results || vulnData?.findings || [];
                if (Array.isArray(findings)) {
                    findings.forEach(f => {
                        const sev = f.severity || 'INFO';
                        termLine(terminal, `  [${sev}] ${f.title || f.name || f.type}`,
                            sev === 'CRITICAL' || sev === 'HIGH' ? 'error' : sev === 'MEDIUM' ? 'warning' : 'info');
                        state.vulnResults.push({ target, ...f, found: now() });
                    });
                    renderVulnSummary(terminal, findings);
                }
                termProgress(terminal, 'Scan complete', 100);
                const count = Array.isArray(findings) ? findings.length : 0;
                state.scanHistory.push({ id: scanId, target, type: 'vuln', status: 'done', findings: count, time: now(), data: vulnData });
                if (count > 0) {
                    const badge = document.getElementById('results-badge');
                    if (badge) { badge.style.display = 'inline'; badge.textContent = state.vulnResults.length; }
                }
            } catch (e) {
                termLine(terminal, `[${now()}] Scanner module: ${e.message}`, 'warning');
            }
        }

        termLine(terminal, `[${now()}] ─────────────────────────────────`, 'dim');
        termLine(terminal, `[${now()}] Scan complete for ${target}`, 'success');
        document.getElementById('scan-status-text').textContent = 'Completed';
        document.getElementById('scan-spinner').style.display = 'none';
        toast(`Scan complete: ${target}`, 'success');
    } catch (e) {
        termLine(terminal, `[${now()}] Error: ${e.message}`, 'error');
        toast('Scan failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '⚡ Launch Scan';
    }
}

// ─── WebSocket Streaming ────────────────────────
function streamScanResults(scanId, terminal, target) {
    return new Promise((resolve) => {
        const wsUrl = `ws://${location.host}/api/v1/recon/ws/${scanId}?token=${getApiKey()}`;
        let ws;
        try { ws = new WebSocket(wsUrl); }
        catch (e) { termLine(terminal, `[${now()}] WebSocket unavailable`, 'warning'); return resolve(); }

        window._activeScanWS = window._activeScanWS || {};
        window._activeScanWS[scanId] = ws;

        const ctrlId = `scan-ctrl-${scanId}`;
        if (!document.getElementById(ctrlId)) {
            const ctrl = document.createElement('div');
            ctrl.id = ctrlId;
            ctrl.style.cssText = 'display:flex;gap:8px;margin-bottom:8px';
            ctrl.innerHTML = `
        <button id="btn-pause-${scanId}" class="btn" style="font-size:11px;padding:4px 12px"
          data-ws-action="pause" data-ws-id="${scanId}">⏸ Pause</button>
        <button id="btn-resume-${scanId}" class="btn" style="font-size:11px;padding:4px 12px;display:none"
          data-ws-action="resume" data-ws-id="${scanId}">▶ Resume</button>
        <button class="btn" style="font-size:11px;padding:4px 12px;
          background:rgba(239,68,68,0.15);border-color:var(--accent-red);color:var(--accent-red)"
          data-ws-action="cancel" data-ws-id="${scanId}">✕ Cancel</button>
      `;
            ctrl.addEventListener('click', (e) => {
                const btn = e.target.closest('[data-ws-action]');
                if (btn) {
                    const action = btn.dataset.wsAction;
                    window._activeScanWS?.[btn.dataset.wsId]?.send(JSON.stringify({ action }));
                }
            });
            terminal.parentElement?.insertBefore(ctrl, terminal);
        }

        ws.onmessage = ({ data }) => {
            let event;
            try { event = JSON.parse(data); } catch { return; }

            if (event.type === 'module_complete') {
                const pct = Math.round((event.index / event.total) * 100);
                termLine(terminal, `[${now()}] ✓ ${event.module.replace(/_/g, ' ')} — ${event.findings_count} finding${event.findings_count !== 1 ? 's' : ''}  [${pct}%]`,
                    event.findings_count > 0 ? 'warning' : 'success');
                const findings = event.data?.findings || event.data?.vulnerabilities || [];
                findings.slice(0, 3).forEach(f => {
                    const sev = (f.severity || 'INFO').toUpperCase();
                    termLine(terminal, `    [${sev}] ${f.title || f.name || f.type || 'Finding'}`,
                        ['CRITICAL', 'HIGH'].includes(sev) ? 'error' : sev === 'MEDIUM' ? 'warning' : 'dim');
                    state.vulnResults.push({ target, ...f, found: now() });
                });
                if (findings.length > 3) termLine(terminal, `    ... and ${findings.length - 3} more`, 'dim');
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
                termLine(terminal, `[${now()}] 🛑 Scan cancelled — ${event.modules_completed} module(s), ${event.findings_so_far} finding(s)`, 'warning');
                cleanupScanWS(scanId); toast('Scan cancelled', 'info'); resolve();
            } else if (event.type === 'done') {
                termLine(terminal, `[${now()}] ✓ Scan complete — ${event.total_findings} total findings`, 'success');
                state.scanHistory.push({ id: event.scan_id, target, type: 'recon', status: 'done', findings: event.total_findings, time: now() });
                cleanupScanWS(scanId); toast('Scan complete', 'success'); resolve();
            } else if (event.type === 'error') {
                termLine(terminal, `[${now()}] ✗ ${event.error}`, 'error'); cleanupScanWS(scanId); resolve();
            } else if (event.type === 'ping') {
                ws.send(JSON.stringify({ action: 'ping' }));
            }
        };

        ws.onerror = () => { termLine(terminal, `[${now()}] WebSocket error`, 'warning'); cleanupScanWS(scanId); resolve(); };
        ws.onclose = (e) => { if (e.code === 4001) termLine(terminal, `[${now()}] ✗ WebSocket auth failed`, 'error'); document.getElementById(`scan-ctrl-${scanId}`)?.remove(); resolve(); };
        setTimeout(() => { if (ws.readyState === WebSocket.OPEN) { ws.close(); resolve(); } }, 600_000);
    });
}

function cleanupScanWS(scanId) {
    const ws = window._activeScanWS?.[scanId];
    if (ws?.readyState === WebSocket.OPEN) ws.close();
    delete window._activeScanWS?.[scanId];
    document.getElementById(`scan-ctrl-${scanId}`)?.remove();
}

// ─── Scan Queue ─────────────────────────────────
let queuePollInterval = null;

export async function submitScanQueue() {
    const raw = document.getElementById('queue-targets')?.value?.trim();
    if (!raw) return toast('Enter at least one target', 'error');
    const targets = raw.split('\n').map(t => t.trim()).filter(t => t.length > 0);
    if (targets.length === 0) return toast('No valid targets found', 'error');
    if (targets.length > 50) return toast('Maximum 50 targets per batch', 'error');

    const scanType = document.getElementById('queue-scan-type')?.value || 'recon';
    const priority = document.getElementById('queue-priority')?.value || 'normal';
    toast(`Submitting ${targets.length} target(s)...`, 'info');

    try {
        const data = await api('/api/v1/ops/queue/submit', { method: 'POST', body: { targets, scan_type: scanType, priority } });
        toast(`${data.submitted} scan(s) queued`, 'success');
        document.getElementById('queue-targets').value = '';
        loadQueueStatus();
        startQueuePolling();
    } catch (e) {
        toast('Queue submission failed: ' + e.message, 'error');
    }
}

export async function loadQueueStatus() {
    try {
        const data = await api('/api/v1/ops/queue/status');
        const jobs = data.jobs || [];
        const counts = data.status_counts || {};
        const summary = document.getElementById('queue-summary');
        if (summary) {
            const runningCount = counts.running || counts.active || 0;
            const doneCount = counts.completed || 0;
            summary.textContent = jobs.length === 0 ? 'Queue is empty' : `${jobs.length} job${jobs.length !== 1 ? 's' : ''} -- ${runningCount} running, ${doneCount} completed`;
        }

        const tbody = document.getElementById('queue-table-body');
        if (!tbody) return;
        if (jobs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:16px">No jobs in queue</td></tr>`;
            stopQueuePolling(); return;
        }

        tbody.innerHTML = jobs.map(job => {
            const cfg = job.config || {};
            const jobStatus = job.status || 'active';
            const statusColor = jobStatus === 'completed' ? 'var(--accent-green)' : jobStatus === 'failed' ? 'var(--accent-red)' : jobStatus === 'running' ? 'var(--accent-orange)' : 'var(--text-muted)';
            return `<tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px">${job.target || cfg.target || '--'}</td>
        <td><span style="background:rgba(59,130,246,0.15);color:var(--accent-blue);padding:1px 6px;border-radius:3px;font-size:11px">${(cfg.scan_type || 'recon').toUpperCase()}</span></td>
        <td><span style="color:${statusColor};font-size:12px;font-weight:600">${jobStatus}</span></td>
        <td style="font-size:11px;color:var(--text-muted)">${job.created_at ? new Date(job.created_at).toLocaleTimeString() : '--'}</td>
        <td>${jobStatus !== 'completed' ? `<button data-cancel-job="${job.id}" style="background:none;border:none;color:var(--accent-red);cursor:pointer;font-size:11px">X</button>` : ''}</td>
      </tr>`;
        }).join('');

        tbody.addEventListener('click', async (e) => {
            const btn = e.target.closest('[data-cancel-job]');
            if (btn) { await cancelQueueJob(btn.dataset.cancelJob); }
        });
    } catch (e) {
        console.warn('Queue status error:', e.message);
    }
}

async function cancelQueueJob(jobId) {
    try { await api(`/api/v1/ops/queue/${jobId}/cancel`, { method: 'POST' }); toast('Job cancelled', 'info'); loadQueueStatus(); }
    catch (e) { toast('Cancel failed: ' + e.message, 'error'); }
}

function startQueuePolling() { if (queuePollInterval) return; queuePollInterval = setInterval(loadQueueStatus, 10_000); }
function stopQueuePolling() { if (queuePollInterval) { clearInterval(queuePollInterval); queuePollInterval = null; } }

export function initScanPage() {
    onPageEnter('scan', loadQueueStatus);

    // Bind launch button
    const btn = document.getElementById('launch-scan-btn');
    if (btn) btn.addEventListener('click', launchScan);

    // Bind queue submit
    const qBtn = document.getElementById('btn-submit-queue');
    if (qBtn) qBtn.addEventListener('click', submitScanQueue);

    // Bind queue refresh
    const rBtn = document.getElementById('btn-refresh-queue');
    if (rBtn) rBtn.addEventListener('click', loadQueueStatus);
}
