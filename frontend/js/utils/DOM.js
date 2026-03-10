import { globalState } from '../core/State.js';

export function toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) {
        console.warn('Toast container not found in DOM');
        return;
    }

    const icons = { success: '✓', error: '✗', info: 'ℹ', warning: '⚠' };
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${message}`;
    container.appendChild(el);

    // Automatically fade out and remove
    setTimeout(() => {
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 300);
    }, 3500);
}

export function termLine(terminal, text, cls = '') {
    if (!terminal) return;

    const line = document.createElement('div');
    line.className = cls ? `line-${cls}` : '';
    line.textContent = text;
    terminal.appendChild(line);

    // Auto-scroll to the bottom
    terminal.scrollTop = terminal.scrollHeight;
}

/**
 * Initializes listeners for DOM/UI events published via the global state
 */
export function initDOMListeners() {
    globalState.subscribe('ui:toast', (data) => {
        const { message, type } = data;
        if (message) {
            toast(message, type);
        }
    });

    globalState.subscribe('ui:terminal', (data) => {
        const { terminalId, text, cls } = data;
        const terminal = document.getElementById(terminalId || 'scan-terminal');
        if (terminal && text) {
            termLine(terminal, text, cls);
        }
    });
}
