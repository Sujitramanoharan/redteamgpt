import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The API runs separately in development (see README). Override the target
// with VITE_API_TARGET if 7861 is taken on your machine.
const target = process.env.VITE_API_TARGET || 'http://127.0.0.1:7861'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      '/api': { target, changeOrigin: true },
      '/v1': { target, changeOrigin: true },
      '/health': { target, changeOrigin: true },
      '/ready': { target, changeOrigin: true },
    }
  }
})
