import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-pulse-chain/',
  test: {
    // Colocated unit tests only — keeps the Playwright specs in e2e/ out of
    // the Vitest run.
    include: ['src/**/*.test.ts'],
    // Pairings on BLS12-381 in pure JS take tens of milliseconds each; the
    // threshold suite performs dozens. Budget measured, not guessed: see README.
    testTimeout: 60_000,
  },
})
