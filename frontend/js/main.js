/**
 * OfSec V3 — Main Entry Point
 * =============================
 * Imports all modules, wires up auth, initializes the app.
 */

// ─── CSS Imports (Vite handles these) ───────────
// Old styles first (base layer), new system overrides
import '../css/style.css';
import '../css/design-system.css';
import '../css/components.css';
import '../css/layout.css';
import '../css/animations.css';

// ─── Core Modules ───────────────────────────────
import { api, setApiKey, setupGlobalErrorHandlers } from './api.js';
import { toast } from './ui.js';
import { navigate, initRouter, VALID_PAGES } from './router.js';

// ─── Page Modules ───────────────────────────────
import { loadDashboard, loadPersistedData, updateRecentScans, initDashboardPage } from './pages/dashboard.js';
import { loadModuleGrid, initScanPage } from './pages/scan.js';
import { updateResults, initResultsPage } from './pages/results.js';
import { initThreatsPage } from './pages/threats.js';
import { loadAIModules, initAIPage } from './pages/ai.js';
import { initDefensePage } from './pages/defense.js';
import { initReportsPage } from './pages/reports.js';
import { loadAPIKeyStatus, loadPlatformInfo, loadDLQ, initSettingsPage } from './pages/settings.js';

// ─── Global Shared State ────────────────────────
export const state = {
    scanHistory: [],
    vulnResults: [],
    iocHistory: [],
};

// ─── Initialize App ─────────────────────────────
function init() {
    // 1. Global error catching
    setupGlobalErrorHandlers();

    // 2. Router setup
    initRouter();

    // 3. Page module initialization (binds event listeners)
    initDashboardPage();
    initScanPage();
    initResultsPage();
    initThreatsPage();
    initAIPage();
    initDefensePage();
    initReportsPage();
    initSettingsPage();

    // 4. Login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const apiKeyInput = document.getElementById('login-apikey').value.trim();
            if (!apiKeyInput) return toast('Please enter an API key', 'error');
            setApiKey(apiKeyInput);

            try {
                const r = await api('/api/v1/status');
                if (r.status === 'operational') {
                    document.getElementById('login-page').style.display = 'none';
                    document.getElementById('app-layout').style.display = 'flex';
                    toast('Welcome to OfSec V3', 'success');

                    // Navigate
                    const hashPage = location.hash.replace('#', '');
                    navigate(VALID_PAGES.includes(hashPage) ? hashPage : 'dashboard');

                    // Load initial data
                    loadDashboard();
                    loadPersistedData();
                    loadModuleGrid();
                    loadAIModules();
                    loadAPIKeyStatus();
                    loadPlatformInfo();
                    loadDLQ();

                    // Periodic polling
                    setInterval(() => { loadDLQ(); }, 30000);
                }
            } catch (err) {
                toast('Authentication failed: ' + err.message, 'error');
            }
        });
    }
}

// ─── Boot ───────────────────────────────────────
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
