import { globalState } from './State.js';

class Router {
    constructor() {
        this.routes = {};
        this.currentRoute = null;

        // Listen to hash changes in the URL
        window.addEventListener('hashchange', () => this.handleHashChange());

        // Setup global click delegation for navigation links (data-page attributes)
        this.setupNavigationLinks();
    }

    setupNavigationLinks() {
        document.addEventListener('click', (e) => {
            const navItem = e.target.closest('[data-page]');
            if (navItem) {
                const page = navItem.getAttribute('data-page');
                if (page) {
                    e.preventDefault();
                    this.navigate(page);
                }
            }
        });
    }

    /**
     * Map a hash route to a controller handler
     * @param {string} path - The route path (e.g. 'dashboard')
     * @param {Function} controller - Function to run when navigated
     */
    register(path, controller) {
        this.routes[path] = controller;
    }

    /**
     * Default listener for hash changes
     */
    handleHashChange() {
        const path = window.location.hash.replace('#', '') || 'dashboard';
        this.navigate(path, false);
    }

    /**
     * Core mapping and navigation logic
     * @param {string} path - Route to go to
     * @param {boolean} updateHash - Whether to modify history/hash visually
     */
    navigate(path, updateHash = true) {
        if (!this.routes[path]) {
            console.warn(`[Router] No route registered: '${path}'.`);
            if (this.routes['dashboard']) {
                path = 'dashboard';
            } else {
                return;
            }
        }

        this.currentRoute = path;

        // Hide all previously active sections and navs
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

        // Show the target section via id
        const pageEl = document.getElementById(`page-${path}`);
        if (pageEl) {
            pageEl.classList.add('active');

            // Re-trigger fade-in animation
            const content = pageEl.querySelector('.page-content');
            if (content) {
                content.classList.remove('fade-in');
                void content.offsetWidth; // force reflow
                content.classList.add('fade-in');
            }
        }

        // Highlight active nav item
        const navEl = document.querySelector(`.nav-item[data-page="${path}"]`);
        if (navEl) {
            navEl.classList.add('active');
        }

        // Silently update URL if programmatically calling navigate()
        if (updateHash && window.location.hash !== `#${path}`) {
            history.replaceState(null, '', `#${path}`);
        }

        // Execute route controller
        if (typeof this.routes[path] === 'function') {
            try {
                this.routes[path]();
            } catch (err) {
                console.error(`[Router] Error executing controller for '${path}':`, err);
            }
        }

        // Broadcast to event bus
        globalState.publish('route:changed', { path });
    }

    /**
     * Kickstarts routing engine
     */
    start() {
        this.handleHashChange();
    }
}

export const router = new Router();
export default Router;
