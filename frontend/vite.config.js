import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
    root: '.',
    publicDir: 'img',

    server: {
        port: 3000,
        strictPort: false,
        open: false,
        proxy: {
            '/api': {
                target: 'http://127.0.0.1:8000',
                changeOrigin: true,
            },
            '/health': {
                target: 'http://127.0.0.1:8000',
                changeOrigin: true,
            },
            '/ws': {
                target: 'ws://127.0.0.1:8000',
                ws: true,
            },
        },
    },

    build: {
        outDir: 'dist',
        emptyOutDir: true,
        rollupOptions: {
            input: resolve(__dirname, 'index.html'),
            output: {
                manualChunks: {
                    core: ['./js/core/State.js', './js/core/Router.js', './js/core/ApiClient.js'],
                    icons: ['lucide'],
                },
            },
        },
    },

    css: {
        devSourcemap: true,
    },
});
