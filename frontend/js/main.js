import { api } from './core/ApiClient.js';
import router from './core/Router.js';
import { initDOMListeners, toast } from './utils/DOM.js';

import { initDashboard } from './features/DashboardController.js';
import { initScan } from './features/ScanController.js';
import { initResults } from './features/ResultsController.js';
import { initThreats } from './features/ThreatsController.js';
import { initAI } from './features/AIController.js';
import { initDefense } from './features/DefenseController.js';
import { initReports } from './features/ReportsController.js';
import { initSettings } from './features/SettingsController.js';

document.addEventListener('DOMContentLoaded', () => {
    // Initialize global UI event listeners (toast, terminal, global search)
    initDOMListeners();

    // Register all routes
    router.register('dashboard', initDashboard);
    router.register('scan', initScan);
    router.register('results', initResults);
    router.register('threats', initThreats);
    router.register('ai', initAI);
    router.register('defense', initDefense);
    router.register('reports', initReports);
    router.register('settings', initSettings);

    // Authentication Setup
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const apiKeyInput = document.getElementById('login-apikey');
            const apiKey = apiKeyInput ? apiKeyInput.value.trim() : '';

            if (!apiKey) {
                toast('Please enter an API key', 'error');
                return;
            }

            // Temporarily store in localStorage so api client can pick it up
            localStorage.setItem('API_KEY', apiKey);

            try {
                const r = await api.get('/status');
                if (r && r.status === 'operational') {
                    const loginPage = document.getElementById('login-page');
                    const appLayout = document.getElementById('app-layout');
                    if (loginPage) loginPage.style.display = 'none';
                    if (appLayout) appLayout.style.display = 'flex';
                    toast('Welcome to OfSec V3', 'success');

                    // Start the application routing
                    router.start();
                }
            } catch (err) {
                // If it failed, clear the token
                localStorage.removeItem('API_KEY');
                toast('Authentication failed: ' + err.message, 'error');
            }
        });
    }

    // Pre-check if already logged in (optional persistence layer)
    const existingKey = localStorage.getItem('API_KEY');
    if (existingKey) {
        // Optionally we can auto-verify and skip login layout if valid
        api.get('/status')
            .then((r) => {
                if (r && r.status === 'operational') {
                    const loginPage = document.getElementById('login-page');
                    const appLayout = document.getElementById('app-layout');
                    if (loginPage) loginPage.style.display = 'none';
                    if (appLayout) appLayout.style.display = 'flex';
                    router.start();
                }
            })
            .catch(() => {
                // Token invalid, clear it
                localStorage.removeItem('API_KEY');
            });
    }
});
