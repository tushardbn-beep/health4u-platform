import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()], server: { allowedHosts: ['.e2b.app'], proxy: { '/api': 'http://localhost:4000' } } });
