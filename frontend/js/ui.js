/**
 * OfSec V3 — UI Utilities Module
 * ================================
 * Toast notifications, terminal helpers, loading states.
 */

// ─── Toast Notifications ────────────────────────
export function toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const icons = { success: '✓', error: '✗', info: 'ℹ' };
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${message}`;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3500);
}

// ─── Terminal Output ────────────────────────────
export function termLine(terminal, text, cls = '') {
    const line = document.createElement('div');
    line.className = cls ? `line-${cls}` : '';
    line.textContent = text;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

export function termProgress(terminal, label, percent) {
    const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
    termLine(terminal, `  [${bar}] ${percent}% — ${label}`, 'info');
}

// ─── Time Helper ────────────────────────────────
export function now() {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
}

// ─── Skeleton Loader ────────────────────────────
export function showSkeleton(container, count = 3) {
    container.innerHTML = Array.from({ length: count }, () =>
        `<div class="skeleton-card"><div class="skeleton-line w75"></div><div class="skeleton-line w50"></div></div>`
    ).join('');
}

// ─── Animated Counter ───────────────────────────
export function animateCounter(element, target, duration = 600) {
    const start = parseInt(element.textContent) || 0;
    if (start === target) return;
    const startTime = performance.now();
    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
        element.textContent = Math.round(start + (target - start) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}
