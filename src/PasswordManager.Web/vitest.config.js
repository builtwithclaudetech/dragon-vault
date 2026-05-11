import { defineConfig } from 'vitest/config';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
    test: {
        environment: 'jsdom',
        include: ['wwwroot/js/__tests__/**/*.test.js'],
        globals: false,
    },
    resolve: {
        alias: {
            // Map the /js/ import prefix used by all modules to the actual filesystem path
            '/js/': resolve(__dirname, 'wwwroot/js') + '/',
        },
    },
});
