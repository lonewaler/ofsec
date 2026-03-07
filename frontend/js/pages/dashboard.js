/**
 * OfSec V3 — Dashboard Page Module
 */
import { api } from '../api.js';
import { toast, now, animateCounter } from '../ui.js';
import { onPageEnter } from '../router.js';
import { state } from '../main.js';

export async function loadDashboard() {
    try {
        const [health, status] = await Promise.all([
            api('/health'),
            api('/api/v1/status')
        ]);

        const modules = status.modules || {};
        const moduleCount = Object.keys(modules).length;

        animateCounter(document.getElementById('kpi-modules'), moduleCount);
        animateCounter(document.getElementById('kpi-scans'), state.scanHistory.length);
        animateCounter(document.getElementById('kpi-vulns'), state.vulnResults.length);

        const criticalCount = state.vulnResults.filter(v =>
            v.severity === 'CRITICAL' || v.severity === 'HIGH'
        ).length;
        const kpiAlerts = document.getElementById('kpi-alerts');
        if (kpiAlerts) {
            animateCounter(kpiAlerts, criticalCount);
            kpiAlerts.style.color = criticalCount > 0 ? 'var(--accent-red)' : '';
        }

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

        const kpiIocs = document.getElementById('kpi-iocs');
        if (kpiIocs) animateCounter(kpiIocs, state.iocHistory.length);
    } catch (e) {
        console.warn('Dashboard load error:', e);
    }
}

export function updateDashboardKPIs() {
    const critCount = state.vulnResults.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length;
    const kpiScans = document.getElementById('kpi-scans');
    if (kpiScans) kpiScans.textContent = state.scanHistory.length;
    const kpiVulns = document.getElementById('kpi-vulns');
    if (kpiVulns) kpiVulns.textContent = state.vulnResults.length;
    const kpiCrit = document.getElementById('kpi-critical');
    if (kpiCrit) {
        kpiCrit.textContent = critCount;
        kpiCrit.style.color = critCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)';
    }
}

export function updateRecentScans() {
    const body = document.getElementById('recent-scans-body');
    if (!body || state.scanHistory.length === 0) return;

    body.innerHTML = state.scanHistory.slice(-10).reverse().map(s => `
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${s.target}</td>
      <td><span class="badge-severity badge-info">${s.type}</span></td>
      <td><span class="status-dot ${s.status === 'done' ? 'active' : 'pending'}"></span>${s.status}</td>
      <td>${s.findings}</td>
      <td style="color:var(--text-muted);font-size:12px">${s.time}</td>
    </tr>
  `).join('');
}

export async function loadPersistedData() {
    try {
        const scansRes = await api('/api/v1/recon/results?limit=50');
        const vulnRes = await api('/api/v1/scanner/vulnerabilities?limit=100');

        if (scansRes?.items?.length > 0) {
            scansRes.items.forEach(s => {
                if (!state.scanHistory.find(h => h.id === s.id)) {
                    state.scanHistory.push({
                        id: s.id, target: s.target, type: s.scan_type || 'recon',
                        status: s.status, findings: s.result_summary?.findings_count || 0,
                        time: s.started_at ? new Date(s.started_at).toLocaleTimeString() : '—',
                        data: s.result_summary,
                    });
                }
            });
        }

        if (vulnRes?.items?.length > 0) {
            vulnRes.items.forEach(v => {
                if (!state.vulnResults.find(r => r.id === v.id)) {
                    state.vulnResults.push({
                        id: v.id, target: v.url || 'unknown', severity: v.severity,
                        title: v.title, cvss: v.cvss,
                        found: v.discovered_at ? new Date(v.discovered_at).toLocaleTimeString() : '—',
                    });
                }
            });
        }

        const iocRes = await api('/api/v1/defense/ioc/history?limit=50').catch(() => null);
        if (iocRes?.items?.length > 0) {
            iocRes.items.forEach(i => {
                if (!state.iocHistory.find(h => h.ioc === i.value)) {
                    state.iocHistory.push({
                        ioc: i.value, type: i.ioc_type,
                        risk: i.confidence > 0.7 ? 'HIGH RISK' : i.confidence > 0.3 ? 'MEDIUM RISK' : 'LOW RISK',
                        riskColor: i.confidence > 0.7 ? 'var(--accent-red)' : i.confidence > 0.3 ? 'var(--accent-orange)' : 'var(--accent-green)',
                        timestamp: i.last_seen ? new Date(i.last_seen).toLocaleTimeString() : '—',
                    });
                }
            });
        }

        updateDashboardKPIs();
        toast(`Loaded ${state.scanHistory.length} scans, ${state.vulnResults.length} findings from DB`, 'info');
    } catch (e) {
        console.warn('Could not load persisted data:', e.message);
    }
}

export function initDashboardPage() {
    onPageEnter('dashboard', loadDashboard);
}
