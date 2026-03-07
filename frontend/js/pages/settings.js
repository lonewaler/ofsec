/**
 * OfSec V3 — Settings Page Module
 */
import { api } from '../api.js';
import { toast } from '../ui.js';
import { onPageEnter } from '../router.js';
import { runIntelSweep } from './threats.js';

// ─── API Key Validation ─────────────────────────
const KEY_DEFS = [
    { name: 'Gemini AI', key: 'GEMINI_API_KEY', critical: true, testFn: testGemini },
    { name: 'Shodan', key: 'SHODAN_API_KEY', critical: false, testFn: testShodan },
    { name: 'VirusTotal', key: 'VIRUSTOTAL_API_KEY', critical: false, testFn: testVirusTotal },
    { name: 'AbuseIPDB', key: 'ABUSEIPDB_API_KEY', critical: false, testFn: testAbuseIPDB },
    { name: 'Censys', key: 'CENSYS_API_ID', critical: false, testFn: testCensys },
    { name: 'NVD', key: 'NVD_API_KEY', critical: false, testFn: testNVD },
    { name: 'AlienVault OTX', key: 'OTX_API_KEY', critical: false, testFn: null },
    { name: 'Hunter.io', key: 'HUNTER_API_KEY', critical: false, testFn: null },
];

const keyStatuses = {};

export function loadAPIKeyStatus() {
    const container = document.getElementById('api-key-status');
    if (!container) return;

    function renderKeyGrid() {
        container.innerHTML = KEY_DEFS.map(k => {
            const s = keyStatuses[k.key] || 'idle';
            const dot = s === 'ok' ? '🟢' : s === 'error' ? '🔴' : s === 'testing' ? '🟡' : s === 'untestable' ? '🟠' : '⚪';
            const label = s === 'ok' ? 'Connected' : s === 'error' ? 'Failed / Not Set' : s === 'testing' ? 'Testing...' : s === 'untestable' ? 'Not testable' : 'Untested';
            const labelColor = s === 'ok' ? 'var(--accent-green)' : s === 'error' ? 'var(--accent-red)' : s === 'testing' ? 'var(--accent-orange)' : 'var(--text-muted)';
            const canTest = k.testFn !== null;
            return `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(55,65,81,0.2);border-radius:var(--radius-sm);margin-bottom:6px">
        <div style="display:flex;align-items:center;gap:8px"><span style="font-size:16px">${dot}</span><div><div style="font-size:13px;font-weight:500">${k.name}</div><div style="font-size:11px;color:var(--text-muted)">${k.key}</div></div></div>
        <div style="display:flex;align-items:center;gap:10px"><span style="font-size:11px;color:${labelColor}">${label}</span>
        ${canTest ? `<button class="btn" style="padding:3px 10px;font-size:11px" data-test-key="${k.key}"${s === 'testing' ? ' disabled' : ''}>${s === 'testing' ? '...' : 'Test'}</button>` : ''}
        </div></div>`;
        }).join('');
    }

    renderKeyGrid();

    container.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-test-key]');
        if (btn) testKey(btn.dataset.testKey);
    });

    KEY_DEFS.forEach(k => {
        if (k.testFn) testKey(k.key);
        else keyStatuses[k.key] = 'untestable';
    });
    renderKeyGrid();
}

async function testKey(keyName) {
    const def = KEY_DEFS.find(k => k.key === keyName);
    if (!def || !def.testFn) return;
    keyStatuses[keyName] = 'testing';
    loadAPIKeyStatus();
    try {
        const result = await def.testFn();
        keyStatuses[keyName] = result ? 'ok' : 'error';
    } catch { keyStatuses[keyName] = 'error'; }
    loadAPIKeyStatus();
}

async function testGemini() { try { const r = await api('/api/v1/ai/analyze/instant', { method: 'POST', body: { target: 'test', findings: [], analysis_type: 'general' } }); return !r?.error?.toLowerCase().includes('api key'); } catch { return false; } }
async function testShodan() { try { const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } }); return !r?.sources?.shodan?.error; } catch { return false; } }
async function testVirusTotal() { try { const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } }); return !r?.sources?.virustotal?.error; } catch { return false; } }
async function testAbuseIPDB() { try { const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } }); return r?.sources?.abuseipdb !== undefined && !r?.sources?.abuseipdb?.error; } catch { return false; } }
async function testCensys() { try { const r = await api('/api/v1/recon/passive', { method: 'POST', body: { target: '8.8.8.8', modules: ['osint'] } }); return r?.sources?.censys !== undefined && !r?.sources?.censys?.error; } catch { return false; } }
async function testNVD() { try { const r = await api('/api/v1/ai/cve/analyze', { method: 'POST', body: ['CVE-2021-44228'] }); return Array.isArray(r?.cves) && r.cves.length > 0; } catch { return false; } }

// ─── Platform Info ──────────────────────────────
export async function loadPlatformInfo() {
    const container = document.getElementById('platform-info');
    if (!container) return;
    try {
        const health = await api('/health');
        const status = await api('/api/v1/status');
        container.innerHTML = `<div style="font-size:13px;line-height:2">
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Version</span><span>${health.version}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Environment</span><span>${health.environment}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Status</span><span style="color:var(--accent-green)">${health.status}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Database</span><span>${health.services?.database || 'unknown'}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">API Version</span><span>${status.api_version}</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">Modules</span><span>${Object.keys(status.modules || {}).length} active</span></div>
      <div style="display:flex;justify-content:space-between"><span style="color:var(--text-muted)">API Docs</span><a href="/docs" target="_blank" style="color:var(--accent-blue)">Open Swagger UI →</a></div>
    </div>`;
    } catch {
        container.innerHTML = '<p style="color:var(--text-muted)">Unable to load platform info</p>';
    }
}

// ─── Schedules ──────────────────────────────────
export async function loadSchedules() {
    const el = document.getElementById('schedule-list');
    if (!el) return;
    try {
        const data = await api('/api/v1/ops/schedules');
        const jobs = data.schedules || [];
        if (jobs.length === 0) { el.innerHTML = '<span style="color:var(--text-dim)">No scheduled scans</span>'; return; }
        el.innerHTML = jobs.map(j => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border-color)">
        <div><strong>${j.kwargs?.target || j.job_id}</strong><span style="color:var(--text-dim);margin-left:8px">${j.status}</span></div>
        <div style="display:flex;gap:8px;align-items:center">
          <span style="font-size:11px;color:var(--text-dim)">Next: ${j.next_run ? new Date(j.next_run).toLocaleString() : 'N/A'}</span>
          <button class="btn btn-secondary" style="font-size:11px;padding:2px 8px" data-delete-sched="${j.job_id}">✕</button>
        </div>
      </div>
    `).join('');
        el.addEventListener('click', async (e) => {
            const btn = e.target.closest('[data-delete-sched]');
            if (btn) await deleteSchedule(btn.dataset.deleteSched);
        });
    } catch (e) { el.innerHTML = `<span style="color:var(--accent-red)">${e.message}</span>`; }
}

export async function createSchedule() {
    const target = document.getElementById('sched-target')?.value?.trim();
    const cron = document.getElementById('sched-cron')?.value?.trim() || '0 2 * * *';
    if (!target) return toast('Target required', 'warning');
    try {
        await api('/api/v1/ops/schedules', { method: 'POST', body: { target, scan_type: 'recon', schedule_type: 'cron', schedule_value: cron } });
        toast('Schedule created', 'success');
        document.getElementById('sched-target').value = '';
        document.getElementById('sched-cron').value = '';
        loadSchedules();
    } catch (e) { toast('Failed: ' + e.message, 'error'); }
}

async function deleteSchedule(jobId) {
    try { await api(`/api/v1/ops/schedules/${jobId}`, { method: 'DELETE' }); toast('Schedule removed', 'success'); loadSchedules(); }
    catch (e) { toast('Failed: ' + e.message, 'error'); }
}

// ─── Account Management ─────────────────────────
export async function loadAccountInfo() {
    const el = document.getElementById('account-info');
    if (!el) return;
    try {
        const data = await api('/api/v1/auth/me');
        el.innerHTML = `<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px">
      <span style="color:var(--text-dim)">Email:</span><span>${data.email}</span>
      <span style="color:var(--text-dim)">Role:</span><span>${data.role}</span>
      <span style="color:var(--text-dim)">Name:</span><span>${data.display_name || '—'}</span>
    </div>`;
    } catch { el.innerHTML = '<span style="color:var(--accent-red)">Failed to load account info</span>'; }
}

export async function changePassword() {
    const oldPw = document.getElementById('pw-old')?.value;
    const newPw = document.getElementById('pw-new')?.value;
    if (!oldPw || !newPw) return toast('Both fields required', 'warning');
    if (newPw.length < 8) return toast('Password must be at least 8 characters', 'warning');
    try {
        await api('/api/v1/auth/change-password', { method: 'POST', body: { old_password: oldPw, new_password: newPw } });
        toast('Password changed', 'success');
        document.getElementById('pw-old').value = '';
        document.getElementById('pw-new').value = '';
    } catch (e) { toast('Failed: ' + e.message, 'error'); }
}

// ─── Intel Sweep Status ─────────────────────────
export async function loadIntelSweepStatus() {
    try {
        const data = await api('/api/v1/defense/intel/sweep/status');
        const el = document.getElementById('intel-sweep-status');
        if (!el) return;
        const next = data.next_run ? new Date(data.next_run).toLocaleString() : 'unknown';
        el.textContent = `Auto-sweep: daily at 03:00 UTC · Next: ${next}`;
    } catch { }
}

// ─── Notification Config ────────────────────────
export async function loadNotifConfig() {
    const el = document.getElementById('notif-config-display');
    if (!el) return;
    try {
        const cfg = await api('/api/v1/ops/notifications/config');
        const row = (label, value, ok) => `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid rgba(55,65,81,0.3)">
      <span style="font-size:12px;color:var(--text-secondary)">${label}</span>
      <span style="font-size:12px;color:${ok ? 'var(--accent-green)' : 'var(--text-muted)'}">${ok ? '● ' : '○ '}${value}</span></div>`;
        el.innerHTML = `
      ${row('Email', cfg.email.enabled ? `${cfg.email.to || 'no recipient'}` : 'Disabled', cfg.email.enabled && cfg.email.configured)}
      ${row('Webhook', cfg.webhook.enabled ? (cfg.webhook.url_configured ? cfg.webhook.url_preview : 'no URL') : 'Disabled', cfg.webhook.enabled && cfg.webhook.url_configured)}
      ${row('Webhook 2', cfg.webhook.url_2_configured ? 'Configured' : 'Not set', cfg.webhook.url_2_configured)}`;
    } catch {
        el.innerHTML = '<span style="color:var(--accent-red);font-size:13px">Could not load config</span>';
    }
}

export async function sendTestAlert() {
    try {
        const data = await api('/api/v1/ops/notifications/test', { method: 'POST' });
        if (data.status === 'no_channels') toast('No channels configured', 'warning');
        else toast(`Test alert sent to: ${data.channels.join(', ')}`, 'success');
    } catch (e) { toast('Test failed: ' + e.message, 'error'); }
}

// ─── Dead-Letter Queue ──────────────────────────
export async function loadDLQ() {
    const el = document.getElementById('dlq-display');
    const btnRetry = document.getElementById('btn-retry-dlq');

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
        if (navBadge) {
            if (data.count > 0) { navBadge.textContent = data.count > 99 ? '99+' : data.count; navBadge.style.display = 'inline-flex'; }
            else navBadge.style.display = 'none';
        }
        if (!el) return;
        if (!data.failed || data.failed.length === 0) {
            el.innerHTML = '<span style="color:var(--text-dim)">DLQ is empty. All webhooks are sending successfully.</span>';
            if (btnRetry) btnRetry.style.display = 'none';
            return;
        }
        if (btnRetry) btnRetry.style.display = 'inline-block';
        el.innerHTML = `<div style="margin-bottom:12px;color:var(--accent-orange);font-weight:600">⚠️ ${data.count} webhook${data.count !== 1 ? 's' : ''} in queue</div>
      <div style="max-height:200px;overflow-y:auto;border:1px solid rgba(55,65,81,0.5);border-radius:4px">
        <table style="width:100%;font-size:11px;border-collapse:collapse">
          <thead style="background:rgba(0,0,0,0.2)"><tr><th style="padding:6px;text-align:left">ID</th><th style="padding:6px;text-align:left">Target</th></tr></thead>
          <tbody>${data.failed.map(item => `<tr style="border-bottom:1px solid rgba(55,65,81,0.3)"><td style="padding:6px;font-family:monospace;color:var(--text-muted)">${item.id}</td><td style="padding:6px;color:var(--text-secondary);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.target_url}</td></tr>`).join('')}</tbody>
        </table></div>`;
    } catch (e) {
        if (el) el.innerHTML = `<span style="color:var(--accent-red)">Could not load DLQ: ${e.message}</span>`;
    }
}

export async function retryDLQ() {
    const btnRetry = document.getElementById('btn-retry-dlq');
    if (btnRetry) { btnRetry.disabled = true; btnRetry.textContent = '⏳ Retrying...'; }
    try {
        const data = await api('/api/v1/ops/notifications/retry', { method: 'POST' });
        toast(data.message, data.still_failing === 0 ? 'success' : 'warning');
        await loadDLQ();
    } catch (e) { toast('Retry failed: ' + e.message, 'error'); }
    finally { if (btnRetry) { btnRetry.disabled = false; btnRetry.textContent = '▶ Retry All'; } }
}

export function initSettingsPage() {
    onPageEnter('settings', () => {
        loadSchedules();
        loadAccountInfo();
        loadIntelSweepStatus();
        loadNotifConfig();
    });

    document.getElementById('btn-create-schedule')?.addEventListener('click', createSchedule);
    document.getElementById('btn-change-password')?.addEventListener('click', changePassword);
    document.getElementById('btn-test-alert')?.addEventListener('click', sendTestAlert);
    document.getElementById('btn-retry-dlq')?.addEventListener('click', retryDLQ);
    document.getElementById('btn-retest-keys')?.addEventListener('click', loadAPIKeyStatus);
    document.getElementById('btn-refresh-schedules')?.addEventListener('click', loadSchedules);
    document.getElementById('btn-refresh-notif')?.addEventListener('click', loadNotifConfig);
    document.getElementById('btn-refresh-dlq')?.addEventListener('click', loadDLQ);
    document.getElementById('btn-intel-sweep')?.addEventListener('click', runIntelSweep);
}
