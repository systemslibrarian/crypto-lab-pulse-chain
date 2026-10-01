import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one rendering a reduced-motion reader actually gets — `.panel` and
 *     `.reveal` with their animations cancelled by the stylesheet's own rule —
 *     was never once the rendering that got scanned. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.1), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all six tabpanels on screen AT ONCE — a
 *     rendering no reader can reach and axe then scans instead of the real one
 *     — and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each disclosure through its `<summary>`,
 *     which is the route a reader has, and scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end — so the invalid-key rendering, the malformed-hex branch, the
 *     rejected-preset pipeline and the stepper's intermediate reveals were all
 *     overwritten before anything measured them, and a click that silently did
 *     nothing looked identical to one that worked. This drive names every
 *     control it touches, asserts a real completion signal after each, and
 *     scans after every step, in {dark, light} x {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. axe files contrast it
 *     cannot resolve (the shared top bar's `color-mix()` ink, for one) under
 *     `incomplete` rather than judging it, and an `aria-label` on a role-less
 *     element lands there too.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     `color-mix()`, to composited backdrops, to every button, select and
 *     toggle, and to all states past first paint.
 *     `nontext.ts` replaces it with a measured oracle over every control at
 *     every driven state, and `expectNoHorizontalOverflow` adds the 1.4.10
 *     check axe has no rule for.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels `.panel` / `.reveal` animations and every transition, so
 * `getAnimations()` is normally empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * declares no animations at all; the assertion runs anyway so that adding one
 * stays a measurement rather than a reading of the stylesheet.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is decorative
 * verdict and tag glyphs beside their own words — see `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's hero
 * IS a `<header class="cl-hero">` directly inside `#app`, so it would imply a
 * second banner; the bar's `dedupeBanner()` demotes it to `role="group"`.
 * Asserting the OUTCOME rather than the markup is what catches the day that
 * script stops running or the hero moves.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * This lab's styled lists are the `ul.checks` verdict lists (Acts 4 and 6)
 * and the scope list, all `list-style: none` — exactly the declaration that
 * makes Safari and VoiceOver DROP a list's implicit role — so each carries an
 * explicit `role="list"` with `role="listitem"` children. Asserted is the
 * SHAPE of that fix: any explicit role on a `ul`/`ol` must be `list`, and a
 * `role="list"` must never sit on an empty element, because axe applies
 * `aria-required-children` to the explicit role. Ask the DOM rather than
 * grepping the source: the roles are set by an element-creation helper.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` is a measured no-op on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE navigation and then asserted
 * from inside the page.
 *
 * This lab renders all six acts at first paint, and two of them (Acts 2 and 4)
 * finish asynchronously because WebCrypto's RSA verify returns a promise; the
 * four-property table waits on one too. `#exhibits[data-ready]` is set only
 * after the last of those resolves, and every act's arrival verdict is then
 * asserted by wording — so a renderer that threw, or a scan that raced the
 * verify, cannot pass as an empty, perfectly accessible region.
 */
export async function boot(page: Page, theme: 'dark'): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('#exhibits')).toHaveAttribute('data-ready', 'true');
  await expect(page.locator('section[data-act]')).toHaveCount(6);
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme: no theme control of any kind may exist.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle], #cl-theme-toggle')
  ).toHaveCount(0);

  // ── The arrival verdicts, by wording ────────────────────────────────────
  await expect(page.locator('[data-check="a1-output"]')).toContainText('MATCH');
  await expect(page.locator('[data-check="a2-chain"]')).toContainText('INTACT');
  await expect(page.locator('[data-check="a3-skiplist"]')).toContainText('PATH VERIFIES');
  await expect(page.locator('[data-check="a4-headline"]')).toContainText('VERIFIED — AND KNOWN TO THE OPERATOR FIRST');
  await expect(page.locator('[data-check="a5-pairing"]')).toContainText('VALID ROUND');
  await expect(page.locator('[data-check="a6-group"]')).toContainText('VALID GROUP SIGNATURE');
  await expect(page.locator('td[data-property]')).toHaveCount(10);
  await expect(page.locator('[data-claim="live-finding"] [data-check="f-sig"]')).toHaveAttribute('data-verdict', 'fail');
  // The guided experiment ships unstarted: only its opening is on the page.
  await expect(page.locator('#guided .gstep')).toHaveCount(0);

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.locator('#a1-pulse-latest')).toBeChecked();
  await expect(page.locator('#a1-layout-deployed')).toBeChecked();
  await expect(page.locator('#a4-pulse-signed')).toBeChecked();
  await expect(page.locator('#a5-chain-default')).toBeChecked();
  await expect(page.locator('#a3-drop')).toHaveValue('');
  await expect(page.locator('#act6 .signer[aria-pressed="true"]')).toHaveCount(3);
  await expect(page.locator('#app .btn-toggle[aria-pressed="true"]:not(.signer)')).toHaveCount(0);

  // ── Disclosures ship shut ───────────────────────────────────────────────
  await expect(page.locator('#app details[open]')).toHaveCount(0);

  await assertListSemantics(page);
  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are 64-byte hex runs — every `.field-value` and `.eq-derivation`
 * relies on `overflow-wrap: anywhere` instead of a scroll region, and the
 * `.sig-pair` grid collapses to one column at 640px — so the shapes at risk
 * are a new unwrapped `<code>` run or a grid item whose automatic minimum size
 * is the min-content of a 128-char line. At 380px that is precisely what this
 * check exists to catch.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab currently avoids scrollers on purpose — long hex wraps via
 * `overflow-wrap: anywhere` — so the assertion is usually vacuous here. It
 * runs at every state anyway, because the requirement MATERIALISES the moment
 * someone reaches for `overflow-x: auto` on a wide value or table (the
 * stylesheet already carries an unused `.table-wrap` rule inviting exactly
 * that), and a scroller born without a keyboard route is invisible to axe.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 * *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe could not finish — including `aria-prohibited-attr`, which is where
 *    an `aria-label` on a role-less element hides. This page leans on getting
 *    that right: the Act 6 signer row and every scroll region pair their
 *    `aria-label` with `role="group"` / `role="region"`.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Open a disclosure the way a reader does — through its summary. */
async function openDetails(page: Page, scope: string, summary: string): Promise<void> {
  const d = page.locator(`${scope} details.expert`, { hasText: summary });
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Drive the lab through every state it renders, scanning each.
 *
 *  - THE ARRIVAL STATE FIRST: all six acts rendered, every disclosure shut.
 *  - EVERY FAILURE VERDICT the page can show, each reached through its real
 *    control: the 8-byte layout and the flipped bit (Act 1), a rewritten pulse
 *    (Act 2), a dropped skiplist hop (Act 3), the post-rotation pulses whose
 *    signature cannot be checked (Act 4), a wrong round and a wrong previous
 *    signature (Act 5), and a below-threshold quorum (Act 6).
 *  - EVERY DISCLOSURE, opened through its summary and scanned open.
 *  - HOVER AND FOCUS, which repaint the controls they touch.
 *  - NO FIXED TIMEOUTS. Every wait is on a verdict's wording.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: six acts rendered, every disclosure shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused');

  // ── Guided experiment, step by step ─────────────────────────────────────
  await page.locator('.cl-hero-cta a', { hasText: 'Start the experiment' }).hover();
  await scanAt('hero call-to-action hovered');
  await page.locator('#guided').getByRole('button', { name: 'Start the experiment' }).click();
  await page.getByRole('button', { name: 'Verify this pulse' }).click();
  await expect(page.locator('[data-check="g-verified"]')).toContainText('VERIFIED');
  await scanAt('Guided 1: pulse verified, question open');
  await page.locator('#guided').getByRole('button', { name: 'Not necessarily' }).click();
  await page.getByRole('button', { name: 'Tamper with it: flip one bit' }).click();
  await expect(page.locator('[data-check="g-tamper"]')).toContainText('TAMPERING DETECTED');
  await scanAt('Guided 2: one bit flipped, tampering detected');
  await page.getByRole('button', { name: 'Restore the original pulse' }).click();
  await page.locator('#guided-3').getByRole('button', { name: 'No', exact: true }).click();
  await expect(page.locator('[data-claim="g-lesson"]')).toContainText('Nothing failed');
  await scanAt('Guided 3: everything passes — the operator knew first');
  await page.getByRole('button', { name: 'What if no single operator holds the key?' }).click();
  for (const n of ['A', 'B']) await page.getByRole('button', { name: `Operator ${n}` }).click();
  await page.getByRole('button', { name: 'Sign with these operators' }).click();
  await expect(page.locator('[data-check="g-group"]')).toHaveAttribute('data-verdict', 'fail');
  await scanAt('Guided 4: two operators — no valid signature');
  await page.getByRole('button', { name: 'Operator C' }).click();
  await page.getByRole('button', { name: 'Sign with these operators' }).click();
  for (const n of ['A', 'C', 'D', 'E']) await page.getByRole('button', { name: `Operator ${n}` }).click();
  await page.getByRole('button', { name: 'Sign with these operators' }).click();
  await expect(page.locator('[data-claim="g-same"]')).toContainText('SAME OUTPUT');
  await openDetails(page, '#guided-4', 'Want to see what actually happened?');
  await scanAt('Guided 4: same output from two quorums, maths open, finale shown');
  await page.getByRole('button', { name: 'Operator B' }).hover();
  await scanAt('a pressed operator circle hovered');

  // ── Act 1 ───────────────────────────────────────────────────────────────
  await page.locator('label[for="a1-layout-draft"]').click();
  await expect(page.locator('[data-check="a1-output"]')).toContainText('MISMATCH');
  await scanAt('Act 1: 8-byte draft layout — mismatch');
  await page.locator('label[for="a1-layout-deployed"]').click();
  await page.locator('#act1').getByRole('button', { name: 'Flip one bit of localRandomValue' }).click();
  await expect(page.locator('[data-check="a1-output"]')).toContainText('MISMATCH');
  await scanAt('Act 1: one bit flipped — mismatch, tampered row tinted');
  await page.locator('#act1').getByRole('button', { name: 'Flip one bit of localRandomValue' }).click();
  await expect(page.locator('[data-check="a1-output"]')).toContainText('MATCH');
  await openDetails(page, '#act1', 'Spec vs deployment');
  await scanAt('Act 1: spec-vs-deployment disclosure open');

  // ── Act 2 ───────────────────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Rewrite it (forger re-hashes)' }).click();
  await expect(page.locator('[data-check="a2-chain"]')).toContainText('REWRITE DETECTED');
  await scanAt('Act 2: a pulse rewritten — three checks fail');
  await openDetails(page, '#act2', 'What each column checks');
  await page.getByRole('button', { name: 'Restore the real chain' }).click();
  await expect(page.locator('[data-check="a2-chain"]')).toContainText('INTACT');
  await scanAt('Act 2: restored, disclosure open');

  // ── Act 3 ───────────────────────────────────────────────────────────────
  await page.locator('#a3-drop').selectOption({ index: 10 });
  await expect(page.locator('[data-check="a3-skiplist"]')).toContainText('PATH BROKEN');
  await scanAt('Act 3: a hop removed — path broken');
  await page.locator('#a3-drop').selectOption('');
  await expect(page.locator('[data-check="a3-skiplist"]')).toContainText('PATH VERIFIES');
  await openDetails(page, '#act3', 'How the path was built');
  await scanAt('Act 3: disclosure open');

  // ── Act 4 ───────────────────────────────────────────────────────────────
  await openDetails(page, '#act4', 'Open the signature by hand');
  await expect(page.locator('[data-check="a4-recover"]')).toContainText('Opens correctly');
  await scanAt('Act 4: signed pulse, signature opened by hand');
  await page.locator('label[for="a4-pulse-latest"]').click();
  await expect(page.locator('[data-check="a4-headline"]')).toContainText('ORIGIN CANNOT BE CHECKED');
  await openDetails(page, '#act4', 'Open the signature by hand');
  await scanAt('Act 4: newest pulse — signature cannot be checked');
  await page.locator('label[for="a4-pulse-rotation"]').click();
  await expect(page.locator('[data-check="a4-headline"]')).toContainText('ORIGIN CANNOT BE CHECKED');
  await scanAt('Act 4: rotation pulse, status 6');

  // ── Act 5 ───────────────────────────────────────────────────────────────
  await page.locator('#act5').getByRole('button', { name: 'Claim it is the next round' }).click();
  await expect(page.locator('[data-check="a5-pairing"]')).toContainText('REJECTED');
  await scanAt('Act 5: wrong round — pairing rejected');
  await page.locator('#act5').getByRole('button', { name: 'Claim it is the next round' }).click();
  await page.locator('#act5').getByRole('button', { name: 'Use the wrong previous signature' }).click();
  await expect(page.locator('[data-check="a5-pairing"]')).toContainText('REJECTED');
  await scanAt('Act 5: wrong previous signature — rejected');
  await page.locator('#act5').getByRole('button', { name: 'Use the wrong previous signature' }).click();
  await page.locator('#a5-round').selectOption('1');
  await expect(page.locator('[data-check="a5-continuity"]')).toContainText('ANCHORED AT GENESIS');
  await scanAt('Act 5: round 1 anchored at the genesis seed');
  await page.locator('label[for="a5-chain-quicknet"]').click();
  await expect(page.locator('[data-check="a5-pairing"]')).toContainText('VALID ROUND');
  await expect(page.locator('#act5').getByRole('button', { name: 'Use the wrong previous signature' })).toBeDisabled();
  await openDetails(page, '#act5', 'Chained vs unchained');
  await scanAt('Act 5: quicknet, disabled chained-only control, disclosure open');

  // ── Act 6 ───────────────────────────────────────────────────────────────
  await page.locator('#act6 .signer', { hasText: 'Signer 1' }).click();
  await page.getByRole('button', { name: 'Combine partial signatures' }).click();
  await expect(page.locator('[data-check="a6-group"]')).toContainText('NOT A GROUP SIGNATURE');
  await scanAt('Act 6: two signers — below threshold, rejected');
  await page.locator('#act6 .signer', { hasText: 'Signer 5' }).click();
  await page.getByRole('button', { name: 'Combine partial signatures' }).click();
  await expect(page.locator('[data-check="a6-group"]')).toContainText('VALID GROUP SIGNATURE');
  await openDetails(page, '#act6', 'Why every quorum agrees');
  await scanAt('Act 6: a second quorum, history table, disclosure open');

  // ── Hover and focus ─────────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Combine partial signatures' }).hover();
  await scanAt('a primary button hovered');
  await page.locator('#act6 .signer', { hasText: 'Signer 2' }).hover();
  await scanAt('a pressed toggle hovered');
  await page.getByRole('button', { name: 'New key shares' }).hover();
  await scanAt('a quiet button hovered');
  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');
  await page.locator('#a3-drop').focus();
  await expect(page.locator('#a3-drop')).toBeFocused();
  await scanAt('a select focused');
  await page.locator('#a1-layout-draft').focus();
  await scanAt('a radio focused');
}
