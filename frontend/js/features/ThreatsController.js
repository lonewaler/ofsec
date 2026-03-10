import api from '../core/ApiClient.js';
import globalState from '../core/State.js';
import { toast } from '../utils/DOM.js';

let iocHistory = []; // Scoped correctly

export function initThreats() {
    const btnCheckIP = document.getElementById('btn-check-ip');
    if (btnCheckIP) btnCheckIP.onclick = checkIP;

    const btnLookupDomain = document.getElementById('btn-lookup-domain');
    if (btnLookupDomain) btnLookupDomain.onclick = lookupDomain;

    const btnTrackIOC = document.getElementById('btn-track-ioc');
    if (btnTrackIOC) btnTrackIOC.onclick = trackIOC;

    // Also hook up ENTER key in inputs if desired
    const ipInput = document.getElementById('ip-check-input');
    if (ipInput) ipInput.onkeypress = (e) => e.key === 'Enter' && checkIP();

    const domainInput = document.getElementById('domain-lookup-input');
    if (domainInput) domainInput.onkeypress = (e) => e.key === 'Enter' && lookupDomain();

    const iocInput = document.getElementById('ioc-track-input');
    if (iocInput) iocInput.onkeypress = (e) => e.key === 'Enter' && trackIOC();

    // Load old history if we want (currently transient in memory)
}

function now() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
}

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
        result.innerHTML = `<div class="terminal"><span class="line-error">Error: ${e.message}</span></div>`;
        toast('IP check failed', 'error');
    }
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

        let html = '';

        let vtScoreHtml = '';
        if (vt?.reputation !== undefined) {
            const vtColor = vt.reputation < 0 ? 'var(--accent-red)' : 'var(--accent-green)';
            vtScoreHtml = `<div style="text-align:center"><div style="font-size:22px;font-weight:700;color:${vtColor}">${vt.reputation}</div><div style="font-size:10px;color:var(--text-muted)">VT Score</div></div>`;
        }
        html += '<div class="card" style="margin-bottom:12px;display:flex;gap:16px;align-items:center">';
        html += '<div style="font-size:28px">🌐</div>';
        html += `<div style="flex:1"><div style="font-size:16px;font-weight:700">${domain}</div>`;
        html += '<div style="font-size:12px;color:var(--text-muted)">';
        if (whois?.registrar) html += `Registrar: ${whois.registrar} &nbsp;|&nbsp; `;
        if (whois?.creation_date) html += `Created: ${whois.creation_date}`;
        html += `</div></div>${vtScoreHtml}</div>`;

        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">';
        html += renderDNSCard(dns);
        html += renderVTCardDomain(vt);
        html += '</div>';

        const allSubs = [...new Set([
            ...(Array.isArray(subdomains) ? subdomains : []),
            ...(shodan?.subdomains || [])
        ])];

        if (allSubs.length > 0) {
            html += '<div class="card" style="margin-bottom:12px">';
            html += `<div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-censys">🔗 SUBDOMAINS</span>`;
            html += `<span style="color:var(--text-muted);font-weight:400;margin-left:6px">(${allSubs.length} total)</span></div>`;
            html += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
            allSubs.slice(0, 24).forEach(s => {
                html += `<span class="subdomain-chip">${s}</span>`;
            });
            html += '</div></div>';
        }

        result.innerHTML = html;
        toast('Domain intelligence complete', 'success');
    } catch (e) {
        result.innerHTML = `<div class="terminal"><span class="line-error">Error: ${e.message}</span></div>`;
        toast('Domain lookup failed', 'error');
    }
}

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

        globalState.publish('data:iocs', iocHistory);

        const kpiIocs = document.getElementById('kpi-iocs');
        if (kpiIocs) kpiIocs.textContent = iocHistory.length;

        const tableBody = document.getElementById('ioc-table-body');
        if (tableBody) {
            let rows = '';
            iocHistory.slice(0, 20).forEach(entry => {
                rows += '<tr>';
                rows += `<td style="font-family:monospace;font-size:12px">${entry.ioc}</td>`;
                rows += `<td><span class="source-badge source-censys">${entry.type.toUpperCase()}</span></td>`;
                rows += `<td><span style="color:${entry.riskColor};font-weight:600;font-size:12px">${entry.risk}</span></td>`;
                rows += `<td style="color:var(--text-muted);font-size:11px">${entry.timestamp}</td>`;
                rows += '</tr>';
            });
            tableBody.innerHTML = rows;
        }

        container.innerHTML = `<span class="line-success">✓ IOC tracked: ${iocValue} — <span style="color:${riskColor}">${riskLabel}</span></span>`;
        input.value = '';
        toast('IOC tracked: ' + riskLabel, risk > 0.3 ? 'error' : 'success');
    } catch (e) {
        container.innerHTML = `<span class="line-error">Error: ${e.message}</span>`;
        toast('IOC tracking failed', 'error');
    }
}

// ─── Render Helpers ─────────────────────────────
function renderRiskBar(pct, color) {
    return `<div class="card" style="margin-bottom:12px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
    <span style="font-weight:600">Aggregate Risk Score</span>
    <span style="color:${color};font-size:20px;font-weight:700">${pct}%</span>
    </div>
    <div style="background:rgba(255,255,255,0.1);border-radius:4px;height:8px">
    <div class="risk-bar-fill" style="background:${color};width:${pct}%;height:100%;border-radius:4px"></div>
    </div></div>`;
}

function renderShodanCard(shodan) {
    let html = `<div class="card"><div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-shodan">📡 SHODAN</span></div>`;
    if (shodan?.error) {
        html += `<span class="line-warning">${shodan.error}</span>`;
    } else {
        html += '<div style="font-size:12px;line-height:2">';
        html += `<div><span style="color:var(--text-muted)">Org:</span> ${shodan?.org || '—'}</div>`;
        html += `<div><span style="color:var(--text-muted)">Country:</span> ${shodan?.country || '—'}</div>`;
        html += `<div><span style="color:var(--text-muted)">ISP:</span> ${shodan?.isp || '—'}</div>`;

        const ports = (shodan?.ports || []).slice(0, 8);
        html += `<div><span style="color:var(--text-muted)">Open Ports:</span> `;
        ports.forEach(p => { html += `<span style="background:rgba(59,130,246,0.2);color:var(--accent-blue);padding:1px 5px;border-radius:3px;font-size:10px;margin:1px">${p}</span>`; });
        html += '</div>';

        const vulns = (shodan?.vulns || []).slice(0, 5);
        if (vulns.length > 0) {
            html += `<div><span style="color:var(--text-muted)">CVEs:</span> `;
            vulns.forEach(v => { html += `<span style="background:rgba(239,68,68,0.2);color:var(--accent-red);padding:1px 5px;border-radius:3px;font-size:10px;margin:1px">${v}</span>`; });
            html += '</div>';
        } else {
            html += `<div><span style="color:var(--text-muted)">CVEs:</span> <span style="color:var(--accent-green)">None detected</span></div>`;
        }
        html += '</div>';
    }
    html += '</div>';
    return html;
}

function renderVTCard(vt) {
    let html = `<div class="card"><div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-virustotal">🦠 VIRUSTOTAL</span></div>`;
    if (vt?.error) {
        html += `<span class="line-warning">${vt.error}</span>`;
    } else {
        const repColor = (vt?.reputation || 0) < 0 ? 'var(--accent-red)' : 'var(--accent-green)';
        html += '<div style="font-size:12px;line-height:2">';
        html += `<div><span style="color:var(--text-muted)">Reputation:</span> <span style="color:${repColor}">${vt?.reputation ?? '—'}</span></div>`;
        html += '<div style="display:flex;gap:8px;margin-top:4px">';
        html += `<span style="background:rgba(239,68,68,0.2);color:var(--accent-red);padding:3px 8px;border-radius:4px;font-size:12px">🔴 ${vt?.detections?.malicious ?? 0} Malicious</span>`;
        html += `<span style="background:rgba(251,191,36,0.2);color:var(--accent-orange);padding:3px 8px;border-radius:4px;font-size:12px">🟡 ${vt?.detections?.suspicious ?? 0} Suspicious</span>`;
        html += '</div>';
        html += `<div style="margin-top:4px"><span style="color:var(--accent-green);font-size:11px">✓ ${vt?.detections?.harmless ?? 0} engines clean</span></div>`;
        if (vt?.asn) html += `<div><span style="color:var(--text-muted)">ASN:</span> ${vt.asn} (${vt?.as_owner || ''})</div>`;
        if (vt?.country) html += `<div><span style="color:var(--text-muted)">Country:</span> ${vt.country}</div>`;
        html += '</div>';
    }
    html += '</div>';
    return html;
}

function renderDNSCard(dns) {
    let html = `<div class="card"><div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-censys">🔍 DNS RECORDS</span></div>`;
    html += '<div style="font-size:12px;line-height:1.8">';
    if (dns?.a) html += `<div><span style="color:var(--text-muted)">A:</span> ${Array.isArray(dns.a) ? dns.a.join(', ') : dns.a}</div>`;
    if (dns?.mx) html += `<div><span style="color:var(--text-muted)">MX:</span> ${Array.isArray(dns.mx) ? dns.mx.slice(0, 3).join(', ') : dns.mx}</div>`;
    if (dns?.ns) html += `<div><span style="color:var(--text-muted)">NS:</span> ${Array.isArray(dns.ns) ? dns.ns.slice(0, 3).join(', ') : dns.ns}</div>`;
    if (dns?.txt) html += `<div><span style="color:var(--text-muted)">TXT:</span> <span style="font-size:10px">${Array.isArray(dns.txt) ? dns.txt.slice(0, 2).join(' | ').substring(0, 120) : dns.txt}</span></div>`;
    if (!dns?.a && !dns?.mx && !dns?.ns) html += '<span class="line-dim">No DNS data returned</span>';
    html += '</div></div>';
    return html;
}

function renderVTCardDomain(vt) {
    let html = `<div class="card"><div style="font-size:11px;font-weight:600;margin-bottom:8px"><span class="source-badge source-virustotal">🦠 VIRUSTOTAL</span></div>`;
    if (vt?.error) {
        html += `<span class="line-warning">${vt.error}</span>`;
    } else {
        html += '<div style="font-size:12px;line-height:1.8">';
        html += '<div style="display:flex;gap:8px;margin-bottom:6px">';
        html += `<span style="background:rgba(239,68,68,0.2);color:var(--accent-red);padding:2px 8px;border-radius:4px">🔴 ${vt?.detections?.malicious ?? 0} Malicious</span>`;
        html += `<span style="background:rgba(251,191,36,0.2);color:var(--accent-orange);padding:2px 8px;border-radius:4px">🟡 ${vt?.detections?.suspicious ?? 0} Suspicious</span>`;
        html += '</div>';
        if (vt?.registrar) html += `<div><span style="color:var(--text-muted)">Registrar:</span> ${vt.registrar}</div>`;
        if (vt?.categories && Object.keys(vt.categories).length) {
            html += `<div><span style="color:var(--text-muted)">Category:</span> ${Object.values(vt.categories).slice(0, 2).join(', ')}</div>`;
        }
        html += '</div>';
    }
    html += '</div>';
    return html;
}
