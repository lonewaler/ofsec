import api from '../core/ApiClient.js';
import globalState from '../core/State.js';
import { toast } from '../utils/DOM.js';

const REPORT_TITLES = {
    executive: '📊 Executive Summary Report',
    technical: '🔧 Technical Report',
    compliance: '✅ Compliance Report',
    vulnerability: '⚠️ Vulnerability Report',
    pentest: '🗡️ Penetration Test Report',
};

export function initReports() {
    // Bind standard buttons
    document.querySelectorAll('[onclick^="generateReport"]').forEach(btn => {
        // extract type from onclick="generateReport('xyz')"
        const match = btn.getAttribute('onclick').match(/'(.*?)'/);
        if (match) {
            const type = match[1];
            btn.onclick = () => generateReport(type);
        }
    });

    const btnExportJson = document.getElementById('btn-export-json');
    if (btnExportJson) btnExportJson.onclick = exportReportJSON;

    const btnExportHtml = document.getElementById('btn-export-html');
    if (btnExportHtml) btnExportHtml.onclick = exportReportHTML;

    const btnExportApi = document.getElementById('btn-export-api');
    if (btnExportApi) btnExportApi.onclick = () => {
        const card = document.getElementById('report-output');
        const type = card?.dataset?.reportType || 'vulnerability';
        exportReportViaAPI(type);
    };
}

function generateReport(type) {
    const card = document.getElementById('report-output');
    const title = document.getElementById('report-title');
    const content = document.getElementById('report-content');
    if (!card) return;

    const vulnResults = globalState.get('data:vulns') || [];
    const scanHistory = globalState.get('data:scans') || [];

    card.style.display = 'block';
    title.textContent = REPORT_TITLES[type] || 'Report';

    const critCount = vulnResults.filter(v => v.severity === 'CRITICAL').length;
    const highCount = vulnResults.filter(v => v.severity === 'HIGH').length;
    const medCount = vulnResults.filter(v => v.severity === 'MEDIUM').length;
    const lowCount = vulnResults.filter(v => v.severity === 'LOW').length;

    let rpt = '<span class="line-info">═══════════════════════════════════════</span><br>';
    rpt += `<span class="line-success">${REPORT_TITLES[type] || 'Report'}</span><br>`;
    rpt += '<span class="line-info">═══════════════════════════════════════</span><br><br>';
    rpt += `<span class="line-dim">Generated: ${new Date().toISOString()}</span><br>`;
    rpt += '<span class="line-dim">Platform: OfSec V3 — Vector Triangulum</span><br><br>';

    rpt += '<span class="line-info">── Scan Summary ──────────────────────</span><br>';
    rpt += `<span>  Total scans run:     ${scanHistory.length}</span><br>`;
    rpt += `<span>  Vulnerabilities:     ${vulnResults.length}</span><br>`;
    rpt += `<span style="color:var(--accent-red)">  Critical:            ${critCount}</span><br>`;
    rpt += `<span style="color:var(--accent-orange)">  High:                ${highCount}</span><br>`;
    rpt += `<span style="color:#f59e0b">  Medium:              ${medCount}</span><br>`;
    rpt += `<span style="color:var(--accent-green)">  Low:                 ${lowCount}</span><br><br>`;

    rpt += '<span class="line-info">── Scanned Targets ───────────────────</span><br>';
    if (scanHistory.length) {
        scanHistory.forEach(s => {
            rpt += `<span>  • ${s.target} &nbsp;[${s.type}] &nbsp;→ ${s.findings} finding${s.findings !== 1 ? 's' : ''} &nbsp;<span style="color:var(--text-muted)">${s.time}</span></span><br>`;
        });
    } else {
        rpt += '<span class="line-dim">  No scans performed yet</span><br>';
    }

    if (vulnResults.length > 0) {
        rpt += '<br><span class="line-info">── Top Findings ──────────────────────</span><br>';
        vulnResults.slice(0, 10).forEach(v => {
            const c = v.severity === 'CRITICAL' ? 'var(--accent-red)' : v.severity === 'HIGH' ? 'var(--accent-orange)' : '#f59e0b';
            rpt += `<span>  [<span style="color:${c}">${v.severity || 'INFO'}</span>] ${v.title || v.name || 'Finding'} — ${v.target}</span><br>`;
        });
    }

    rpt += '<br><span class="line-dim">─── End of Report ───────────────────</span>';
    content.innerHTML = rpt;
    card.dataset.reportType = type;

    toast('Report generated', 'success');
}

function exportReportJSON() {
    const card = document.getElementById('report-output');
    if (!card || card.style.display === 'none') return toast('Generate a report first', 'warning');

    const type = card?.dataset?.reportType || 'report';
    const vulnResults = globalState.get('data:vulns') || [];
    const scanHistory = globalState.get('data:scans') || [];

    const payload = {
        meta: { report_type: type, generated_at: new Date().toISOString(), platform: 'OfSec V3', version: '3.0.0' },
        summary: {
            total_scans: scanHistory.length, total_vulnerabilities: vulnResults.length,
            critical: vulnResults.filter(v => v.severity === 'CRITICAL').length,
            high: vulnResults.filter(v => v.severity === 'HIGH').length,
            medium: vulnResults.filter(v => v.severity === 'MEDIUM').length,
            low: vulnResults.filter(v => v.severity === 'LOW').length,
        },
        scans: scanHistory,
        vulnerabilities: vulnResults,
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ofsec-${type}-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast('JSON report downloaded', 'success');
}

function exportReportHTML() {
    const card = document.getElementById('report-output');
    if (!card || card.style.display === 'none') return toast('Generate a report first', 'warning');

    const type = card?.dataset?.reportType || 'report';
    const titleText = document.getElementById('report-title')?.textContent || 'OfSec Report';
    const contentHTML = document.getElementById('report-content')?.innerHTML || '';

    let html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">`;
    html += `<title>${titleText} — OfSec V3</title>`;
    html += `<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f1117;color:#e2e8f0;font-family:"JetBrains Mono","Courier New",monospace;font-size:13px;line-height:1.6;padding:40px}`;
    html += `header{border-bottom:1px solid #1e293b;padding-bottom:20px;margin-bottom:28px}header h1{font-size:22px;color:#38bdf8}header p{font-size:12px;color:#64748b;margin-top:4px}`;
    html += `.terminal{background:#0a0e1a;border:1px solid #1e293b;border-radius:8px;padding:20px;white-space:pre-wrap;word-break:break-word}`;
    html += `.line-success{color:#4ade80}.line-info{color:#38bdf8}.line-warning{color:#fb923c}.line-error{color:#f87171}.line-dim{color:#475569}`;
    html += `footer{margin-top:32px;font-size:11px;color:#334155;border-top:1px solid #1e293b;padding-top:16px}`;
    html += `@media print{body{background:white;color:black}.terminal{background:#f8f8f8;border-color:#ccc}}</style></head><body>`;
    html += `<header><h1>${titleText}</h1><p>OfSec V3 — Vector Triangulum &nbsp;|&nbsp; Generated: ${new Date().toISOString()}</p></header>`;
    html += `<div class="terminal">${contentHTML}</div>`;
    html += `<footer>This report was generated by OfSec V3. Confidential — for authorized use only.</footer></body></html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `ofsec-${type}-report-${Date.now()}.html`; a.click();
    URL.revokeObjectURL(url);
    toast('HTML report downloaded', 'success');
}

async function exportReportViaAPI(type) {
    const vulnResults = globalState.get('data:vulns') || [];
    const scanHistory = globalState.get('data:scans') || [];

    toast('Generating report via API...', 'info');
    try {
        const data = await api('/api/v1/ops/reports/generate', {
            method: 'POST',
            body: { report_type: type, scan_data: { scans: scanHistory, vulnerabilities: vulnResults, generated_at: new Date().toISOString() } }
        });
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `ofsec-api-${type}-${Date.now()}.json`; a.click();
        URL.revokeObjectURL(url);
        toast('API report downloaded', 'success');
    } catch (e) {
        toast(`API report failed: ${e.message}`, 'error');
    }
}
