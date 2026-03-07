/**
 * OfSec V3 — Results Page Module
 */
import { api } from '../api.js';
import { toast } from '../ui.js';
import { state } from '../main.js';

export function updateResults() {
    const body = document.getElementById('results-body');
    if (!body || state.vulnResults.length === 0) return;

    body.innerHTML = state.vulnResults.map(v => {
        const sev = (v.severity || 'info').toLowerCase();
        const cveMatch = (v.cve || v.title || v.name || '').match(/CVE-\d{4}-\d{4,}/i);
        const cveId = cveMatch ? cveMatch[0].toUpperCase() : null;
        const cveLink = cveId
            ? `<span data-cve-id="${cveId}" style="margin-left:6px;background:rgba(59,130,246,0.2);color:var(--accent-blue);padding:1px 6px;border-radius:3px;font-size:10px;font-family:monospace;cursor:pointer;border:1px solid rgba(59,130,246,0.3)" title="View CVE detail">${cveId} ↗</span>`
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

    // Click delegation for CVE links
    body.addEventListener('click', (e) => {
        const cveEl = e.target.closest('[data-cve-id]');
        if (cveEl) openCVEPanel(cveEl.dataset.cveId);
    });
}

export function refreshResults() {
    updateResults();
    toast('Results refreshed', 'info');
}

// ─── CVE Side Panel ─────────────────────────────
let cvePanel = null;

export function openCVEPanel(cveId) {
    if (!cvePanel) {
        cvePanel = document.createElement('div');
        cvePanel.id = 'cve-panel';
        cvePanel.style.cssText = 'position:fixed;top:0;right:-440px;width:420px;height:100vh;background:var(--bg-card);border-left:1px solid var(--border-color);z-index:1000;transition:right 0.3s cubic-bezier(0.4,0,0.2,1);overflow-y:auto;padding:24px;box-shadow:-8px 0 32px rgba(0,0,0,0.4)';
        document.body.appendChild(cvePanel);
    }
    const bd = document.getElementById('cve-backdrop');
    if (bd) bd.style.display = 'block';
    cvePanel.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
    <div><div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">CVE DETAIL</div>
    <div style="font-family:monospace;font-size:16px;font-weight:700;color:var(--accent-blue)">${cveId}</div></div>
    <button id="cve-close-btn" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;padding:4px">✕</button>
  </div><div id="cve-panel-body"><div class="spinner"></div></div>`;
    document.getElementById('cve-close-btn').addEventListener('click', closeCVEPanel);
    cvePanel.style.right = '0';
    fetchCVEDetail(cveId);
}

export function closeCVEPanel() {
    if (cvePanel) cvePanel.style.right = '-440px';
    const bd = document.getElementById('cve-backdrop');
    if (bd) bd.style.display = 'none';
}

async function fetchCVEDetail(cveId) {
    const body = document.getElementById('cve-panel-body');
    try {
        const data = await api('/api/v1/ai/cve/analyze', { method: 'POST', body: [cveId] });
        const cve = data?.cves?.[0];
        if (!cve || !cve.found) { body.innerHTML = '<div class="terminal"><span class="line-warning">CVE not found in NVD database.</span></div>'; return; }

        const score = cve.cvss?.base_score ?? '—';
        const severity = cve.cvss?.severity ?? 'UNKNOWN';
        const sevColor = severity === 'CRITICAL' ? 'var(--accent-red)' : severity === 'HIGH' ? 'var(--accent-orange)' : severity === 'MEDIUM' ? '#f59e0b' : 'var(--accent-green)';
        const sevBg = severity === 'CRITICAL' ? '239,68,68' : severity === 'HIGH' ? '249,115,22' : '59,130,246';

        let html = `<div style="text-align:center;padding:20px;background:rgba(${sevBg},0.1);border-radius:var(--radius);margin-bottom:16px;border:1px solid ${sevColor}40">
      <div style="font-size:48px;font-weight:900;color:${sevColor};line-height:1">${score}</div>
      <div style="font-size:13px;font-weight:700;color:${sevColor};margin-top:4px">${severity}</div>
      ${cve.cvss?.vector ? `<div style="font-size:10px;color:var(--text-muted);margin-top:6px;font-family:monospace">${cve.cvss.vector}</div>` : ''}
    </div>`;
        html += `<div style="font-size:11px;color:var(--text-muted);margin-bottom:12px">`;
        if (cve.published) html += 'Published: ' + new Date(cve.published).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        if (cve.modified) html += ' &nbsp;|&nbsp; Modified: ' + new Date(cve.modified).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        html += '</div>';
        html += `<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:6px">DESCRIPTION</div>
      <div style="font-size:12px;line-height:1.7;color:var(--text-secondary)">${cve.description || 'No description available.'}</div></div>`;
        if (cve.weaknesses?.length > 0) {
            html += `<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:6px">WEAKNESSES (CWE)</div><div style="display:flex;flex-wrap:wrap;gap:6px">`;
            cve.weaknesses.forEach(w => { html += `<span style="background:rgba(251,191,36,0.15);color:#fbbf24;padding:3px 8px;border-radius:4px;font-size:11px;font-family:monospace">${w}</span>`; });
            html += '</div></div>';
        }
        if (cve.references?.length > 0) {
            html += `<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:6px">REFERENCES</div>`;
            cve.references.slice(0, 5).forEach(ref => {
                const short = ref.replace('https://', '').substring(0, 55) + (ref.length > 60 ? '…' : '');
                html += `<div style="margin-bottom:4px"><a href="${ref}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent-blue);word-break:break-all;text-decoration:none;opacity:0.8">↗ ${short}</a></div>`;
            });
            html += '</div>';
        }
        html += `<div style="display:flex;gap:8px;margin-top:20px;padding-top:16px;border-top:1px solid var(--border-color)">
      <a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" rel="noopener" class="btn btn-primary" style="flex:1;text-align:center;text-decoration:none;font-size:12px">View in NVD ↗</a>
      <button class="btn" style="font-size:12px" id="cve-copy-btn">Copy ID</button>
    </div>`;
        body.innerHTML = html;
        document.getElementById('cve-copy-btn')?.addEventListener('click', () => {
            navigator.clipboard.writeText(cveId).then(() => toast('Copied', 'success'));
        });
    } catch (e) {
        body.innerHTML = `<div class="terminal"><span class="line-error">Error: ${e.message}</span></div>`;
    }
}

export function initResultsPage() {
    const refreshBtn = document.getElementById('btn-refresh-results');
    if (refreshBtn) refreshBtn.addEventListener('click', refreshResults);
}
