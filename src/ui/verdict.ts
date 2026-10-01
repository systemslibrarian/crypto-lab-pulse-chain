/**
 * Verdict markers. Every check the page renders goes through here, so the
 * claims suite can read them uniformly:
 *
 *   data-check   which check this is (stable name)
 *   data-verdict pass | fail | warn
 *   data-code    the exported failure code, when it failed
 *
 * WCAG 1.4.1: icon + word + colour, never colour alone. Tone tracks SYSTEM
 * INTEGRITY: a check that passes is green; a check that fails is red whether
 * the learner caused it or not; and a result that passes every check while a
 * property still fails (the negative-claim fixture) is amber, never green.
 */
import { el } from './dom'

export type Verdict = 'pass' | 'fail' | 'warn'

const ICON: Record<Verdict, string> = { pass: '✓', fail: '✗', warn: '!' }

export function verdictEl(
  check: string,
  v: Verdict,
  label: string,
  detail?: string,
  code?: string,
): HTMLElement {
  return el(
    'p',
    {
      class: `verdict verdict-${v}`,
      'data-check': check,
      'data-verdict': v,
      'data-code': code,
    },
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: ICON[v] }),
    el('strong', { class: 'verdict-label', text: label }),
    code ? el('code', { class: 'verdict-code', text: code }) : null,
    detail ? el('span', { class: 'verdict-detail', text: ` ${detail}` }) : null,
  )
}

/** A small inline pass/fail tag for tables. */
export function tag(check: string, ok: boolean, okText: string, failText: string, code?: string): HTMLElement {
  return el(
    'span',
    {
      class: `tag tag-${ok ? 'pass' : 'fail'}`,
      'data-check': check,
      'data-verdict': ok ? 'pass' : 'fail',
      'data-code': ok ? undefined : code,
    },
    el('span', { 'aria-hidden': 'true', text: ok ? '✓ ' : '✗ ' }),
    ok ? okText : failText,
  )
}

/** A toggle button whose state is aria-pressed. */
export function toggle(label: string, pressed: boolean, onChange: (pressed: boolean) => void): HTMLButtonElement {
  const b = el('button', { type: 'button', class: 'btn btn-toggle', 'aria-pressed': String(pressed), text: label })
  b.addEventListener('click', () => {
    const next = b.getAttribute('aria-pressed') !== 'true'
    b.setAttribute('aria-pressed', String(next))
    onChange(next)
  })
  return b
}

/** A radio group rendered as a fieldset — native keyboard behaviour. */
export function radios<T extends string>(
  name: string,
  legend: string,
  options: Array<{ value: T; text: string }>,
  selected: T,
  onChange: (v: T) => void,
): HTMLFieldSetElement {
  const fs = el('fieldset', { class: 'radios' }, el('legend', { text: legend }))
  for (const o of options) {
    const id = `${name}-${o.value}`
    const input = el('input', { type: 'radio', name, id, value: o.value, checked: o.value === selected })
    input.addEventListener('change', () => {
      if (input.checked) onChange(o.value)
    })
    fs.appendChild(el('label', { class: 'radio', for: id }, input, el('span', { text: o.text })))
  }
  return fs
}

/** A scrollable, keyboard-reachable table wrapper (axe: scrollable-region-focusable). */
export function scroller(label: string, child: HTMLElement): HTMLElement {
  return el('div', { class: 'scroller', tabindex: '0', role: 'region', 'aria-label': label }, child)
}
