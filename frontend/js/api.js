/**
 * OfSec V3 — API Module
 * ======================
 * Network layer: HTTP requests, WebSocket utils, error reporting.
 */

import { toast } from './ui.js';

let API_KEY = 'dev-api-key';

export function getApiKey() { return API_KEY; }
export function setApiKey(key) { API_KEY = key; }

// ─── Core API Helper ────────────────────────────
export async function api(path, opts = {}) {
    let res;
    try {
        res = await fetch(path, {
            ...opts,
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY,
                ...(opts.headers || {})
            },
            body: opts.body ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)) : undefined
        });
    } catch (networkErr) {
        const errMsg = 'Cannot connect to server. Is the backend running?';
        toast(errMsg, 'error');
        reportErrorToBackend({ message: errMsg, source: 'api:' + path });
        throw new Error(errMsg);
    }

    if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get('Retry-After') || '60', 10);
        showRateLimitToast(retryAfter);
        throw new Error(`Rate limited. Retry in ${retryAfter}s`);
    }

    if (!res.ok) {
        const e = await res.json().catch(() => ({ detail: res.statusText }));
        const errMsg = e.error || e.detail || e.message || res.statusText;
        if (res.status === 401 || res.status === 403) {
            toast('Authentication failed — check your API key', 'error');
        } else if (res.status === 404) {
            toast('Resource not found: ' + path, 'error');
        } else if (res.status >= 500) {
            toast('Server error: ' + errMsg, 'error');
        } else {
            toast('Request failed: ' + errMsg, 'error');
        }
        throw new Error(errMsg);
    }
    return res.json();
}

// ─── Rate Limit Toast ───────────────────────────
function showRateLimitToast(seconds) {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = 'toast toast-error';
    el.style.cssText = 'min-width:260px;padding:12px 16px';
    container.appendChild(el);

    let remaining = seconds;
    function tick() {
        el.innerHTML = `⏱ Rate limited — retry in <strong>${remaining}s</strong>`;
        if (remaining <= 0) {
            el.style.opacity = '0';
            setTimeout(() => el.remove(), 300);
        } else {
            remaining--;
            setTimeout(tick, 1000);
        }
    }
    tick();
}

// ─── Error Reporting ────────────────────────────
export function reportErrorToBackend(errorData) {
    try {
        fetch('/api/v1/log/error', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
            body: JSON.stringify({
                message: errorData.message,
                source: errorData.source || 'frontend',
                stack: errorData.stack || '',
                url: errorData.url || window.location.href,
                user_agent: navigator.userAgent
            })
        }).catch(() => { });
    } catch (e) { /* ignore */ }
}

// ─── Global Error Handlers ──────────────────────
export function setupGlobalErrorHandlers() {
    window.onerror = function (message, source, lineno, colno, error) {
        console.error('[OfSec] Unhandled error:', message, source, lineno);
        reportErrorToBackend({
            message: String(message),
            source: `${source}:${lineno}:${colno}`,
            stack: error?.stack || '',
            url: window.location.href
        });
        toast('An unexpected error occurred. Check logs for details.', 'error');
        return false;
    };

    window.addEventListener('unhandledrejection', function (event) {
        console.error('[OfSec] Unhandled promise rejection:', event.reason);
        reportErrorToBackend({
            message: 'Unhandled promise rejection: ' + String(event.reason?.message || event.reason),
            source: 'promise',
            stack: event.reason?.stack || '',
            url: window.location.href
        });
        toast('A background operation failed: ' + (event.reason?.message || 'Unknown error'), 'error');
    });
}
