import { api } from '../core/ApiClient.js';
import { globalState } from '../core/State.js';

let isDashboardLoaded = false;

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

export function getSelectedModules() {
    return MODULES.filter(m => m.selected).map(m => m.id);
}

function loadModuleGrid() {
    const grid = document.getElementById('module-grid');
    if (!grid) return;
    grid.innerHTML = MODULES.map(m => `
        <div class="module-chip ${m.selected ? 'selected' : ''}" data-module-id="${m.id}">
            <span>${m.icon}</span> ${m.name}
        </div>
    `).join('');
}

function toggleModule(id) {
    const mod = MODULES.find(m => m.id === id);
    if (mod) {
        mod.selected = !mod.selected;
        const chip = document.querySelector(`.module-chip[data-module-id="${id}"]`);
        if (chip) {
            chip.classList.toggle('selected');
        }
    }
}

async function loadDashboard() {
    try {
        const [health, status] = await Promise.all([
            api.get('/health').catch(() => ({ status: 'unknown' })),
            api.get('/status').catch(() => ({ modules: {}, api_version: 'unknown' }))
        ]);

        const modules = status.modules || {};
        const moduleCount = Object.keys(modules).length;

        const kpiModules = document.getElementById('kpi-modules');
        if (kpiModules) kpiModules.textContent = moduleCount || '—';

        // Update Scan & Vuln KPIs - querying state from ScanController 
        const scanHistory = globalState.get('data:scans') || [];
        const vulnResults = globalState.get('data:vulns') || [];

        const kpiScans = document.getElementById('kpi-scans');
        if (kpiScans) kpiScans.textContent = scanHistory.length;

        const kpiVulns = document.getElementById('kpi-vulns');
        if (kpiVulns) kpiVulns.textContent = vulnResults.length;

        // Count critical findings
        const criticalCount = vulnResults.filter(v =>
            (v.severity || '').toUpperCase() === 'CRITICAL' ||
            (v.severity || '').toUpperCase() === 'HIGH'
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

        // IOC count
        const iocHistory = globalState.get('data:iocs') || [];
        const kpiIocs = document.getElementById('kpi-iocs');
        if (kpiIocs) kpiIocs.textContent = iocHistory.length;

    } catch (e) {
        console.warn('Dashboard load error:', e);
    }
}

export function updateDashboardKPIs() {
    const scanHistory = globalState.get('data:scans') || [];
    const vulnResults = globalState.get('data:vulns') || [];

    const kpiScans = document.getElementById('kpi-scans');
    if (kpiScans) kpiScans.textContent = scanHistory.length;

    const kpiVulns = document.getElementById('kpi-vulns');
    if (kpiVulns) kpiVulns.textContent = vulnResults.length;

    const criticalCount = vulnResults.filter(v =>
        (v.severity || '').toUpperCase() === 'CRITICAL' ||
        (v.severity || '').toUpperCase() === 'HIGH'
    ).length;
    const kpiAlerts = document.getElementById('kpi-alerts');
    if (kpiAlerts) {
        kpiAlerts.textContent = criticalCount;
        kpiAlerts.style.color = criticalCount > 0 ? 'var(--accent-red)' : '';
    }
}

export function initDashboard(forceRefresh = false) {
    if (isDashboardLoaded && !forceRefresh) {
        return; // Use cached state
    }

    loadModuleGrid();
    loadDashboard();

    // Setup Module Grid Click delegation
    const grid = document.getElementById('module-grid');
    if (grid && !grid.dataset.listenerBound) {
        grid.addEventListener('click', (e) => {
            const chip = e.target.closest('.module-chip');
            if (chip) {
                const id = chip.getAttribute('data-module-id');
                if (id) toggleModule(id);
            }
        });
        grid.dataset.listenerBound = 'true';
    }

    // Support periodic refreshes whenever scans/vulns change
    globalState.subscribe('data:scans', updateDashboardKPIs);
    globalState.subscribe('data:vulns', updateDashboardKPIs);
    globalState.subscribe('data:iocs', updateDashboardKPIs);

    isDashboardLoaded = true;
}
