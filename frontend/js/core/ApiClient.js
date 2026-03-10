/**
 * Robust API Client wrapper around native fetch().
 */
class ApiClient {
    constructor(baseURL = '') {
        this.baseURL = baseURL;
    }

    getAuthToken() {
        return localStorage.getItem('API_KEY');
    }

    async triggerErrorToast(message) {
        try {
            const { globalState } = await import('./State.js');
            globalState.publish('ui:toast', { type: 'error', message });
        } catch (e) {
            console.error('Toast Error:', message);
            // Fallback console log for unhandled toast
        }
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;

        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            ...(options.headers || {})
        };

        const token = this.getAuthToken();
        if (token) {
            headers['X-API-Key'] = token;
        }

        const config = {
            ...options,
            headers
        };

        let response;
        try {
            response = await fetch(url, config);
        } catch (error) {
            this.triggerErrorToast('Network error: Unable to reach the server.');
            throw error;
        }

        if (!response.ok) {
            let errorMessage = `HTTP Error ${response.status}: ${response.statusText}`;
            try {
                const errorBody = await response.json();
                errorMessage = errorBody.detail || errorBody.message || errorMessage;
            } catch (e) {
                // Ignore JSON parsing errors for error bodies
            }

            if (response.status === 401) {
                this.triggerErrorToast('Session expired. Please log in again.');
                try {
                    const { globalState } = await import('./State.js');
                    globalState.publish('auth:logout', { reason: 'expired' });
                } catch (e) { }
            } else {
                this.triggerErrorToast(errorMessage);
            }

            throw new Error(errorMessage);
        }

        if (response.status === 204) {
            return null;
        }

        return await response.json();
    }

    get(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'GET' });
    }

    post(endpoint, data, options = {}) {
        return this.request(endpoint, {
            ...options,
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    put(endpoint, data, options = {}) {
        return this.request(endpoint, {
            ...options,
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    delete(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'DELETE' });
    }
}

// Export a singleton instance using the standard API path. E.g '/api/v1' 
export const api = new ApiClient('/api/v1');
export default ApiClient;
