import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { prototypeMockAPI } from './prototype/mock-api'

export default defineConfig(({ mode }) => {
  // `npm run dev:prototype` serves the business-units prototype from an
  // in-memory mock API instead of proxying to a backend. The mock plugin only
  // applies to the dev server, so no build ever contains it.
  const prototype = mode === 'prototype'
  return {
    plugins: [react(), tailwindcss(), ...(prototype ? [prototypeMockAPI()] : [])],
    // scripts/build-frontend.mjs clears this generated directory before each
    // build while preserving the tracked .gitkeep required by go:embed.
    build: { outDir: 'internal/webui/dist', emptyOutDir: false, sourcemap: false },
    server: prototype ? { port: 5173 } : { port: 5173, proxy: { '/api': 'http://127.0.0.1:8080' } },
  }
})
