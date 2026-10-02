import { defineConfig } from '@playwright/test'

/**
 * E2E gate: the a11y scan (a11y.spec.ts) and the claims suite (claims.spec.ts).
 * Both run against the production build served by `vite preview`, so what
 * passes here is what ships to Pages. Port 4677 is this lab's entry in the
 * fleet registry (crypto-lab/tools/playwright-ports.json), so a stray
 * `reuseExistingServer` never scans a different lab's preview.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4717/crypto-lab-pulse-chain/',
    colorScheme: 'dark',
    // Local-only escape hatch for a machine whose pre-installed Chromium is a
    // different build from the one this Playwright pins. CI never sets it and
    // installs its own (`npx playwright install chromium`).
    ...(process.env.PW_CHROMIUM ? { launchOptions: { executablePath: process.env.PW_CHROMIUM } } : {}),
  },
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: 'npm run build && npm run preview -- --port 4717 --strictPort',
    url: 'http://localhost:4717/crypto-lab-pulse-chain/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
