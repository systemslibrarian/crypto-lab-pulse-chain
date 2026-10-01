/**
 * Act 2 — Walk the hash chain, then try to rewrite history.
 *
 * Eight consecutive real pulses, every one signed under a pinned certificate.
 * Each row shows three independent checks: the RSA signature, the link to the
 * pulse before (previous = prior outputValue), and the precommitment the pulse
 * before made to this pulse's localRandomValue. The learner rewrites one pulse
 * as a forger would — change a value, recompute its outputValue so the pulse
 * is self-consistent — and watches three different checks catch it.
 */
import { abbrev } from '../core/bytes'
import { certFor, NIST } from '../nist/fixtures'
import type { Pulse } from '../nist/types'
import {
  checkOutputValue,
  checkPrecommitment,
  checkPreviousLink,
  checkSignature,
  FAIL,
  flipFirstByte,
  withField,
} from '../nist/verify'
import { button, clear, el, expert, labelledSelect, panel } from './dom'
import { scroller, tag, verdictEl } from './verdict'

const RUN: Pulse[] = NIST.preRotation

export function mountAct2(host: HTMLElement): void {
  const sec = panel(
    'act2',
    'Act 2 · Walk the chain, then rewrite history',
    'Each pulse repeats the previous pulse’s outputValue and commits to the next pulse’s secret. Change one pulse and see what breaks.',
  )
  sec.setAttribute('data-act', '2')
  const { wrap, select } = labelledSelect(
    'a2-target',
    'Pulse to rewrite',
    RUN.slice(1, -1).map((p) => ({ value: String(p.pulseIndex), text: `#${p.pulseIndex} (${p.timeStamp.slice(11, 16)} UTC)` })),
  )
  select.value = String((RUN[3] as Pulse).pulseIndex)
  let forged: number | null = null
  const out = el('div', { class: 'act-out', 'aria-live': 'polite' })
  const status = el('p', { class: 'muted', role: 'status', 'data-claim': 'a2-status' })

  const rewrite = button('Rewrite it (forger re-hashes)', () => {
    forged = Number(select.value)
    void render()
  })
  const reset = button('Restore the real chain', () => {
    forged = null
    void render()
  }, 'btn-quiet')
  select.addEventListener('change', () => {
    if (forged !== null && Number(select.value) !== forged) {
      // A different target retires the old forgery rather than leaving a stale picture.
      forged = null
      status.textContent = 'Target changed — the previous rewrite was undone.'
      void render(false)
    }
  })

  let seq = 0
  async function render(announce = true): Promise<void> {
    const mine = ++seq
    const chain = RUN.map((p) => {
      if (p.pulseIndex !== forged) return p
      const t = withField(p, 'localRandomValue', flipFirstByte(p.localRandomValue))
      return withField(t, 'outputValue', checkOutputValue(t).computed)
    })
    const sigs = await Promise.all(chain.map((p) => checkSignature(p, certFor(p))))
    if (mine !== seq) return
    clear(out)
    const rows = chain.map((p, i) => {
      const prev = chain[i - 1]
      const s = sigs[i]!
      const own = checkOutputValue(p)
      const link = prev ? checkPreviousLink(prev, p) : null
      const pc = prev ? checkPrecommitment(prev, p) : null
      return el(
        'tr',
        { class: p.pulseIndex === forged ? 'row-tampered' : '', 'data-pulse': String(p.pulseIndex) },
        el('th', { scope: 'row', text: `#${p.pulseIndex}` }),
        el('td', { class: 'mono', text: p.timeStamp.slice(11, 19) }),
        el('td', { class: 'mono', text: abbrev(p.outputValue, 10, 6) }),
        el('td', {}, tag('a2-own', own.ok, 'hashes', 'mismatch', own.code)),
        el('td', {}, link ? tag('a2-link', link.ok, 'linked', 'broken', link.code) : el('span', { class: 'muted', text: 'start' })),
        el('td', {}, pc ? tag('a2-precommit', pc.ok, 'opens', 'fails', pc.code) : el('span', { class: 'muted', text: 'start' })),
        el('td', {}, tag('a2-sig', s.ok, 'valid', 'invalid', s.code)),
      )
    })
    const table = el(
      'table',
      { class: 'chain' },
      el('caption', { text: `Pulses #${(RUN[0] as Pulse).pulseIndex}–#${(RUN.at(-1) as Pulse).pulseIndex}, 2026-09-03` }),
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          ...['Pulse', 'Time (UTC)', 'outputValue', 'Self-hash', 'previous link', 'Precommitment', 'RSA signature'].map((h) =>
            el('th', { scope: 'col', text: h }),
          ),
        ),
      ),
      el('tbody', {}, ...rows),
    )
    const failures = out.ownerDocument.createDocumentFragment()
    out.append(scroller('Hash chain of eight real pulses', table))
    if (forged === null) {
      out.append(verdictEl('a2-chain', 'pass', 'INTACT', `All ${chain.length} pulses hash, link, open their precommitments and carry valid NIST signatures.`))
      if (announce) status.textContent = ''
    } else {
      const i = chain.findIndex((p) => p.pulseIndex === forged)
      const caught = [
        sigs[i]!.ok ? null : `its signature (${FAIL.SIG_INVALID})`,
        checkPrecommitment(chain[i - 1]!, chain[i]!).ok ? null : `the previous pulse’s precommitment (${FAIL.PRECOMMIT_MISMATCH})`,
        checkPreviousLink(chain[i]!, chain[i + 1]!).ok ? null : `the next pulse’s previous link (${FAIL.LINK_BROKEN})`,
      ].filter((x): x is string => x !== null)
      out.append(
        verdictEl(
          'a2-chain',
          'fail',
          'REWRITE DETECTED',
          `Pulse #${forged} re-hashes cleanly, but ${caught.length} independent checks catch it: ${caught.join('; ')}.`,
          FAIL.LINK_BROKEN,
        ),
        el(
          'p',
          { class: 'callout' },
          'To hide the broken link the forger would have to rewrite every later pulse too, and each rewritten pulse needs a fresh signature from NIST’s private key. Anyone who saved one later pulse can prove the rewrite.',
        ),
      )
      if (announce) status.textContent = `Rewrote pulse #${forged}: ${caught.length} checks failed.`
    }
    out.append(failures)
  }

  sec.append(
    el('div', { class: 'controls' }, wrap, el('div', { class: 'btnrow' }, rewrite, reset)),
    status,
    out,
    expert(
      'What each column checks',
      el('p', {}, 'Self-hash: SHA-512 of the pulse equals its own outputValue (Act 1). previous link: this pulse’s previous field equals the prior pulse’s outputValue (NISTIR 8213 §5.1). Precommitment: SHA-512 of this pulse’s localRandomValue equals the prior pulse’s precommitmentValue (§4.7). RSA signature: RSASSA-PKCS1-v1_5 with SHA-512 over the nineteen serialized fields, verified with WebCrypto against the certificate the pulse names.'),
      el('p', {}, 'The rewrite flips one bit of localRandomValue and recomputes outputValue, which is the most a forger without NIST’s key can do.'),
    ),
  )
  host.appendChild(sec)
  void render()
}
