import { api } from '../core/ApiClient.js';
import { globalState } from '../core/State.js';
import { toast, termLine } from '../utils/DOM.js';
import { getSelectedModules } from './DashboardController.js';

// Encapsulated state (no globals leaking)
let scanHistory = [];
let vulnResults = [];

// Helper for current time
function now() {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
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
    findings.forEach(f => {
        const sev = f.severity?.toUpperCase() || 'INFO';
        counts[sev] = (counts[sev] || 0) + 1;
    });
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
    const targetInput = document.getElementById('scan-target');
    const typeInput = document.getElementById('scan-type');

    if (!targetInput || !typeInput) return;

    const target = targetInput.value.trim();
    const scanType = typeInput.value;

    if (!target) return toast('Enter a target to scan', 'error');

    const btn = document.getElementById('launch-scan-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<div class="spinner"></div> Scanning...';
    }

    const outputCard = document.getElementById('scan-output-card');
    const terminal = document.getElementById('scan-terminal');
    if (outputCard) outputCard.style.display = 'block';
    if (terminal) terminal.innerHTML = '';

    const selectedMods = getSelectedModules();
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
                const initRes = await api.post('/recon/passive?stream=true', {
                    target, modules: selectedMods
                });

                const dbScanId = initRes.scan_id;
                termLine(terminal, `[${now()}] Scan started (ID: ${dbScanId}) -- streaming results...`, 'success');

                // Open SSE stream
                await streamScanResults(dbScanId, terminal, target);

            } catch (e) {
                termLine(terminal, `[${now()}] SSE not available, falling back to blocking mode...`, 'warning');
                // Fallback: blocking mode
                try {
                    const reconData = await api.post('/recon/passive', {
                        target, modules: selectedMods
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
                    globalState.publish('data:scans', scanHistory);
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
                const vulnData = await api.post('/scanner/scan', {
                    target, scan_types: ['web', 'ssl', 'headers']
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
                    globalState.publish('data:vulns', vulnResults);
                    renderVulnSummary(terminal, findings);
                }

                termProgress(terminal, 'Scan complete', 100);
                const count = Array.isArray(findings) ? findings.length : 0;
                scanHistory.push({ id: scanId, target, type: 'vuln', status: 'done', findings: count, time: now(), data: vulnData });
                globalState.publish('data:scans', scanHistory);

                if (count > 0) {
                    const badge = document.getElementById('results-badge');
                    if (badge) {
                        badge.style.display = 'inline';
                        badge.textContent = vulnResults.length;
                    }
                }
            } catch (e) {
                termLine(terminal, `[${now()}] Scanner module: ${e.message}`, 'warning');
            }
        }

        termLine(terminal, `[${now()}] ─────────────────────────────────`, 'dim');
        termLine(terminal, `[${now()}] Scan complete for ${target}`, 'success');

        const scanStatusText = document.getElementById('scan-status-text');
        if (scanStatusText) scanStatusText.textContent = 'Completed';

        const scanSpinner = document.getElementById('scan-spinner');
        if (scanSpinner) scanSpinner.style.display = 'none';

        // Update tables
        updateRecentScans();
        updateResults();

        toast(`Scan complete: ${target}`, 'success');
    } catch (e) {
        termLine(terminal, `[${now()}] Error: ${e.message}`, 'error');
        toast('Scan failed: ' + e.message, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '⚡ Launch Scan';
        }
    }
}

// Track active websockets in this closure scope rather than window
const activeScanWS = {};

function streamScanResults(scanId, terminal, target) {
    return new Promise((resolve) => {
        const API_KEY = api.getAuthToken() || 'dev-api-key';
        const wsUrl = `ws://${location.host}/api/v1/recon/ws/${scanId}?token=${API_KEY}`;
        let ws;

        try { ws = new WebSocket(wsUrl); }
        catch (e) {
            termLine(terminal, `[${now()}] WebSocket unavailable`, 'warning');
            return resolve();
        }

        activeScanWS[scanId] = ws;

        // Inject pause / resume / cancel controls above terminal
        const ctrlId = `scan-ctrl-${scanId}`;
        if (!document.getElementById(ctrlId)) {
            const ctrl = document.createElement('div');
            ctrl.id = ctrlId;
            ctrl.style.cssText = 'display:flex;gap:8px;margin-bottom:8px';
            ctrl.innerHTML = `
                <button id="btn-pause-${scanId}" class="btn scan-control-btn" data-action="pause" data-scanid="${scanId}" style="font-size:11px;padding:4px 12px">⏸ Pause</button>
                <button id="btn-resume-${scanId}" class="btn scan-control-btn" data-action="resume" data-scanid="${scanId}" style="font-size:11px;padding:4px 12px;display:none">▶ Resume</button>
                <button class="btn scan-control-btn" data-action="cancel" data-scanid="${scanId}" style="font-size:11px;padding:4px 12px;background:rgba(239,68,68,0.15);border-color:var(--accent-red);color:var(--accent-red)">✕ Cancel</button>
            `;
            if (terminal && terminal.parentElement) {
                terminal.parentElement.insertBefore(ctrl, terminal);
            }
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
                globalState.publish('data:vulns', vulnResults);

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
                globalState.publish('data:scans', scanHistory);

                updateRecentScans();
                updateResults();

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
    const ws = activeScanWS[scanId];
    if (ws?.readyState === WebSocket.OPEN) ws.close();
    delete activeScanWS[scanId];
    document.getElementById(`scan-ctrl-${scanId}`)?.remove();
}

function wsScanPause(id) { activeScanWS[id]?.send(JSON.stringify({ action: 'pause' })); }
function wsScanResume(id) { activeScanWS[id]?.send(JSON.stringify({ action: 'resume' })); }
function wsScanCancel(id) { activeScanWS[id]?.send(JSON.stringify({ action: 'cancel' })); }

// ─── Update Tables ──────────────────────────
function updateRecentScans() {
    const body = document.getElementById('recent-scans-body');
    if (!body || scanHistory.length === 0) return;

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
    if (!body || vulnResults.length === 0) return;

    body.innerHTML = vulnResults.map(v => {
        const sev = (v.severity || 'info').toLowerCase();
        const cveMatch = (v.cve || v.title || v.name || '').match(/CVE-\d{4}-\d{4,}/i);
        const cveId = cveMatch ? cveMatch[0].toUpperCase() : null;
        const cveLink = cveId
            ? `<span onclick="globalState.publish('cve:open', '${cveId}')" style="margin-left:6px;background:rgba(59,130,246,0.2);color:var(--accent-blue);padding:1px 6px;border-radius:3px;font-size:10px;font-family:monospace;cursor:pointer;border:1px solid rgba(59,130,246,0.3)" title="View CVE detail">${cveId} ↗</span>`
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

export function refreshResults() {
    updateResults();
    toast('Results refreshed', 'info');
}

export function initScan() {
    // Bind main launch button
    const btn = document.getElementById('launch-scan-btn');
    if (btn && !btn.dataset.listenerBound) {
        btn.addEventListener('click', launchScan);
        btn.dataset.listenerBound = 'true';
    }

    // Bind refresh results button
    const refreshBtn = document.getElementById('btn-refresh-results');
    if (refreshBtn && !refreshBtn.dataset.listenerBound) {
        refreshBtn.addEventListener('click', refreshResults);
        refreshBtn.dataset.listenerBound = 'true';
    }

    // Bind delegation for scan control buttons that are created dynamically
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('scan-control-btn')) {
            const action = e.target.getAttribute('data-action');
            const id = e.target.getAttribute('data-scanid');
            if (action === 'pause') wsScanPause(id);
            else if (action === 'resume') wsScanResume(id);
            else if (action === 'cancel') wsScanCancel(id);
        }
    });

    // Run initial table render
    updateRecentScans();
    updateResults();
}

/**
 * Interface to preload external data into memory buffers
 */
export function preloadScanData(history, results) {
    if (Array.isArray(history)) {
        scanHistory = history;
        globalState.publish('data:scans', scanHistory);
    }
    if (Array.isArray(results)) {
        vulnResults = results;
        globalState.publish('data:vulns', vulnResults);
    }
    updateRecentScans();
    updateResults();
}
