/**
 * Global State Manager based on Publish/Subscribe pattern.
 */
class State {
    constructor() {
        this.events = {};
        this.currentState = {};
    }

    /**
     * Subscribe to a state change event
     * @param {string} event - The event name to subscribe to
     * @param {Function} callback - The callback to execute when the event is published
     * @returns {Function} - A function to unsubscribe
     */
    subscribe(event, callback) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(callback);

        // Optionally call immediately with current state
        if (this.currentState[event] !== undefined) {
            try {
                callback(this.currentState[event]);
            } catch (err) {
                console.error(`Error in State subscriber immediate call for '${event}':`, err);
            }
        }

        return () => this.unsubscribe(event, callback);
    }

    /**
     * Unsubscribe from a state change event
     */
    unsubscribe(event, callback) {
        if (!this.events[event]) return;
        this.events[event] = this.events[event].filter(cb => cb !== callback);
    }

    /**
     * Publish a new state/event
     */
    publish(event, data = {}) {
        this.currentState[event] = data;

        if (!this.events[event]) return;

        this.events[event].forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`Error in State subscriber for '${event}':`, error);
            }
        });
    }

    /**
     * Retrieve the last published data for an event
     */
    get(event) {
        return this.currentState[event];
    }
}

// Export a singleton instance
export const globalState = new State();
export default State;
