import { defineConfig } from 'vitest/config'

export default defineConfig({
  esbuild: { jsx: 'automatic' },
  test: {
    environment: 'node',
    include: ['test/**/*.test.jsx'],
    pool: 'forks',
    minWorkers: 1,
    maxWorkers: 1,
  },
})
