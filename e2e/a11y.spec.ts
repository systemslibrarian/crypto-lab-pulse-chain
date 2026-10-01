import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven through everything it renders: the arrival state with all
 * six acts verified and every disclosure shut; the skip link focused; every
 * failure verdict reached through its real control (the 8-byte draft layout,
 * a flipped bit, a rewritten pulse, a dropped skiplist hop, the post-rotation
 * pulses whose signature cannot be checked, a wrong drand round and previous
 * signature, a below-threshold quorum); every disclosure opened through its
 * summary; and hover and focus states. Every state is scanned at desktop and
 * phone width. Dark is the only theme.
 *
 * See `gate.ts` for why nothing is injected into the page, why no state is
 * revealed from script, why the defaults are asserted rather than assumed,
 * and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
