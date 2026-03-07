/**
 * OfSec V3 — Router Module
 * =========================
 * Hash-based SPA router with lazy page loading and transitions.
 */

const PAGE_TITLES = {
    dashboard: 'Dashboard', scan: 'Launch Scan', results: 'Scan Results',
    threats: 'Threat Intelligence', ai: 'AI Engine', defense: 'Defense Operations',
    reports: 'Reports', settings: 'Settings'
};

const VALID_PAGES = Object.keys(PAGE_TITLES);
let currentPage = 'dashboard';

// Page-specific enter/exit hooks registered by page modules
const pageEnterHooks = {};
const pageExitHooks = {};

export function onPageEnter(page, fn) { pageEnterHooks[page] = fn; }
export function onPageExit(page, fn) { pageExitHooks[page] = fn; }
export function getCurrentPage() { return currentPage; }

export function navigate(page) {
    if (!VALID_PAGES.includes(page)) page = 'dashboard';

    // Exit hook for current page
    if (pageExitHooks[currentPage]) pageExitHooks[currentPage]();

    // Update DOM
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const el = document.getElementById(`page-${page}`);
    if (el) {
        el.classList.add('active');
        // Add staggered fade-in for cards
        el.querySelectorAll('.card, .kpi-card').forEach((card, i) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(12px)';
            setTimeout(() => {
                card.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, i * 60);
        });
    }

    const nav = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (nav) nav.classList.add('active');

    document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;

    // Update URL hash
    if (location.hash !== '#' + page) {
        history.replaceState(null, '', '#' + page);
    }

    currentPage = page;

    // Enter hook for new page
    if (pageEnterHooks[page]) pageEnterHooks[page]();
}

export function initRouter() {
    // Handle browser back/forward
    window.addEventListener('hashchange', () => {
        const page = location.hash.replace('#', '') || 'dashboard';
        if (VALID_PAGES.includes(page)) navigate(page);
    });

    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.getElementById('cve-panel')?.style.setProperty('right', '-440px');
            document.getElementById('cve-backdrop')?.style.setProperty('display', 'none');
        }
    });

    // Click delegation for any element with data-page (sidebar nav + header buttons)
    document.querySelectorAll('[data-page]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navigate(item.dataset.page);
        });
    });

    // CVE backdrop click-to-close
    const backdrop = document.getElementById('cve-backdrop');
    if (backdrop) {
        backdrop.addEventListener('click', () => {
            document.getElementById('cve-panel')?.style.setProperty('right', '-440px');
            backdrop.style.display = 'none';
        });
    }
}

export { VALID_PAGES };
