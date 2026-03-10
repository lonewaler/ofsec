import api from '../core/ApiClient.js';
import globalState from '../core/State.js';
import { toast } from '../utils/DOM.js';

let alertPollInterval = null;
let lastAlertCount = 0;
let lastRefreshTime = null;
let refreshTickInterval = null;

export function initDefense() {
    startAlertPolling();

    // Clean up when leaving page
    globalState.subscribe('route:changed', (newRoute) => {
        if (newRoute !== 'defense') {
            stopAlertPolling();
        } else {
            startAlertPolling();
        }
    });
}

function now() {
    const d = new Date();
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
}

async function loadDefenseAlerts() {
    try {
        let alertsRes, corrRes;
        try { alertsRes = await api('/api/v1/defense/alerts?limit=50'); } catch (e) { alertsRes = { alerts: [] }; }
        try { corrRes = await api('/api/v1/defense/correlation/alerts?limit=20'); } catch (e) { corrRes = { alerts: [] }; }

        const alerts = alertsRes?.alerts || [];
        const corrAlerts = corrRes?.alerts || [];
        const newAlerts = alerts.length > lastAlertCount;

        renderAlertsTable(alerts, newAlerts);
        renderCorrAlertsTable(corrAlerts);
        updateIncidentKPI();

        lastAlertCount = alerts.length;
        lastRefreshTime = Date.now();
        updateRefreshLabel();
    } catch (e) {
        console.warn('Alert poll error:', e);
    }
}

function renderAlertsTable(alerts, hasNew) {
    const body = document.getElementById('alerts-body');
    if (!body) return;

    if (alerts.length === 0) {
        body.innerHTML = '<tr><td colspan="5"><div class="empty-state"><p>No alerts currently. System is monitoring.</p></div></td></tr>';
        return;
    }

    let rows = '';
    alerts.forEach((a, i) => {
        const sev = (a.severity || 'info').toLowerCase();
        const sevColor = sev === 'critical' ? 'var(--accent-red)' : sev === 'high' ? 'var(--accent-orange)' : sev === 'medium' ? '#f59e0b' : 'var(--accent-green)';
        const isNew = hasNew && i < (alerts.length - lastAlertCount);
        const statusBg = a.status === 'open' ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)';
        const statusColor = a.status === 'open' ? 'var(--accent-red)' : 'var(--accent-green)';
        const ts = a.timestamp || a.created_at ? new Date(a.timestamp || a.created_at).toLocaleTimeString() : now();

        rows += `<tr class="${isNew ? 'alert-new' : ''}" style="transition:background 0.5s">
      <td><span style="color:${sevColor};font-weight:700;font-size:12px;text-transform:uppercase">${a.severity || 'INFO'}</span></td>
      <td style="font-size:13px">${a.title || a.type || a.name || 'Alert'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${a.source || a.rule || '—'}</td>
      <td><span style="font-size:11px;padding:2px 7px;border-radius:3px;background:${statusBg};color:${statusColor}">${a.status || 'open'}</span></td>
      <td style="color:var(--text-muted);font-size:11px">${ts}</td>
    </tr>`;
    });

    body.innerHTML = rows;

    if (hasNew) {
        document.querySelectorAll('.alert-new').forEach(row => {
            row.style.background = 'rgba(239,68,68,0.15)';
            setTimeout(() => { row.style.background = ''; }, 2000);
        });
    }
}

function renderCorrAlertsTable(alerts) {
    const body = document.getElementById('correlation-alerts-body');
    if (!body || alerts.length === 0) return;

    let rows = '';
    alerts.forEach(a => {
        const ts = a.triggered_at ? new Date(a.triggered_at).toLocaleTimeString() : now();
        rows += `<tr>
      <td style="font-family:monospace;font-size:11px">${a.rule_id || '—'}</td>
      <td style="font-size:12px">${a.rule_name || a.description || 'Correlation Match'}</td>
      <td style="font-size:11px;color:var(--text-muted)">${a.matched_events || 0} events</td>
      <td style="font-size:11px;color:var(--text-muted)">${ts}</td>
    </tr>`;
    });

    body.innerHTML = rows;
}

function updateRefreshLabel() {
    const label = document.getElementById('alerts-refresh-label');
    if (!label || !lastRefreshTime) return;
    if (refreshTickInterval) clearInterval(refreshTickInterval);
    refreshTickInterval = setInterval(() => {
        const secs = Math.floor((Date.now() - lastRefreshTime) / 1000);
        label.textContent = `Last refreshed ${secs}s ago`;
    }, 1000);
}

async function updateIncidentKPI() {
    try {
        const alertsRes = await api('/api/v1/defense/alerts?limit=100').catch(() => ({ alerts: [] }));
        const openCount = (alertsRes?.alerts || []).filter(a => a.status === 'open').length;
        // We update globalState which updates the dashboard KPI
        globalState.publish('data:incidents', openCount);
    } catch (e) { }
}

export function startAlertPolling() {
    if (alertPollInterval) clearInterval(alertPollInterval);
    loadDefenseAlerts();
    alertPollInterval = setInterval(loadDefenseAlerts, 30000);
}

export function stopAlertPolling() {
    if (alertPollInterval) clearInterval(alertPollInterval);
    if (refreshTickInterval) clearInterval(refreshTickInterval);
}
