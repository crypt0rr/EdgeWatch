import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // scripts/build-frontend.mjs clears this generated directory before each
  // build while preserving the tracked .gitkeep required by go:embed.
  build: { outDir: 'internal/webui/dist', emptyOutDir: false, sourcemap: false },
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8080' } },
})
