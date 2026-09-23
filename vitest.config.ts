import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    exclude: ['e2e/**', 'node_modules/**', 'dist/**', 'scripts/**'],
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'json-summary', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
      thresholds: {
        // Ratcheted 2026-09-23 to two points below the measured main-branch
        // coverage. Lowering these floors requires a written justification.
        statements: 86,
        lines: 89,
        branches: 73,
        functions: 83,
      },
    },
  },
})
