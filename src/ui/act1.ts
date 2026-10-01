/**
 * Act 1 — Recompute a pulse.
 *
 * The headline mechanism for NIST: outputValue is SHA-512 over a precise byte
 * serialization of nineteen fields plus the signature. The learner sees the
 * bytes laid out field by field, the published value beside the recomputed
 * one, and can break it two ways: by changing one bit of the pulse, or by
 * reading the spec's draft text literally (8-byte length prefixes).
 */
import { abbrev, beUint, toHex } from '../core/bytes'
import { NIST } from '../nist/fixtures'
import { DEPLOYED, DRAFT_TEXT, signedSegments, type Layout } from '../nist/serialize'
import type { Pulse } from '../nist/types'
import { checkOutputValue, flipFirstByte, withField } from '../nist/verify'
import { clear, el, expert, hexDiff, panel } from './dom'
import { radios, scroller, toggle, verdictEl } from './verdict'

const PULSES: Array<{ value: string; text: string; pulse: Pulse }> = [
  { value: 'latest', text: `#${(NIST.recent.at(-1) as Pulse).pulseIndex} — newest pinned pulse`, pulse: NIST.recent.at(-1) as Pulse },
  { value: 'signed', text: `#${(NIST.preRotation.at(-1) as Pulse).pulseIndex} — last pulse under the old certificate`, pulse: NIST.preRotation.at(-1) as Pulse },
  { value: 'rotation', text: `#${NIST.rotation.pulseIndex} — the key-rotation pulse`, pulse: NIST.rotation },
]

export function mountAct1(host: HTMLElement): void {
  const sec = panel(
    'act1',
    'Act 1 · Recompute a NIST pulse',
    'A NIST pulse publishes an outputValue and claims it is the SHA-512 hash of everything else in the pulse. Rebuild those bytes yourself and check.',
  )
  sec.setAttribute('data-act', '1')
  let which = 'latest'
  let layout: Layout = DEPLOYED
  let tampered = false

  const out = el('div', { class: 'act-out' })
  const controls = el(
    'div',
    { class: 'controls' },
    radios(
      'a1-pulse',
      'Pulse',
      PULSES.map(({ value, text }) => ({ value, text })),
      which,
      (v) => {
        which = v
        render()
      },
    ),
    radios(
      'a1-layout',
      'Length prefix width',
      [
        { value: 'deployed', text: '4 bytes — what beacon.nist.gov computes' },
        { value: 'draft', text: '8 bytes — the NISTIR 8213 draft text' },
      ],
      'deployed',
      (v) => {
        layout = v === 'draft' ? DRAFT_TEXT : DEPLOYED
        render()
      },
    ),
    el(
      'div',
      { class: 'ctl' },
      el('span', { class: 'ctl-label', id: 'a1-tamper-l', text: 'Break it yourself' }),
      toggle('Flip one bit of localRandomValue', false, (p) => {
        tampered = p
        render()
      }),
    ),
  )

  function render(): void {
    clear(out)
    const base = (PULSES.find((p) => p.value === which) as (typeof PULSES)[number]).pulse
    const pulse = tampered ? withField(base, 'localRandomValue', flipFirstByte(base.localRandomValue)) : base
    const segs = signedSegments(pulse, layout)
    const r = checkOutputValue(pulse, layout)

    const table = el(
      'table',
      { class: 'bytemap', 'data-claim': 'bytemap' },
      el('caption', { text: `The ${segs.length} signed fields, in the order NISTIR 8213 Algorithm 2 serializes them` }),
      el(
        'thead',
        {},
        el('tr', {}, ...['Field', 'Type', 'Offset', 'Length prefix', 'Value bytes'].map((h) => el('th', { scope: 'col', text: h }))),
      ),
      el(
        'tbody',
        {},
        ...segs.map((s) =>
          el(
            'tr',
            { class: s.field === 'localRandomValue' && tampered ? 'row-tampered' : '' },
            el('th', { scope: 'row', text: s.field }),
            el('td', { text: s.kind }),
            el('td', { class: 'num', 'data-offset': String(s.offset), text: String(s.offset) }),
            el('td', { class: 'mono', 'data-prefix': toHex(s.prefix), text: s.prefix.length ? toHex(s.prefix) : '— (fixed width)' }),
            el('td', { class: 'mono', text: `${abbrev(toHex(s.value), 12, 8)} (${s.value.length} B)` }),
          ),
        ),
        el(
          'tr',
          {},
          el('th', { scope: 'row', text: 'signatureValue' }),
          el('td', { text: 'sig' }),
          el('td', { class: 'num', text: String(segs.reduce((n, s) => n + s.prefix.length + s.value.length, 0)) }),
          el('td', { class: 'mono', text: layout.prefixSignatureInOutput ? toHex(beUint(512, layout.lengthPrefix)) : '— (raw, no prefix)' }),
          el('td', { class: 'mono', text: `${abbrev(pulse.signatureValue.toLowerCase(), 12, 8)} (512 B)` }),
        ),
      ),
    )
    out.append(
      scroller('Byte map of the pulse serialization', table),
      el('h3', { text: 'Published vs recomputed outputValue' }),
      hexDiff(r.published, r.computed, 'Published by NIST', `SHA-512 of the bytes above (${layout.lengthPrefix}-byte prefixes)`),
      el('span', { class: 'sr-only', 'data-claim': 'a1-published', text: r.published }),
      el('span', { class: 'sr-only', 'data-claim': 'a1-computed', text: r.computed }),
      r.ok
        ? verdictEl('a1-output', 'pass', 'MATCH', `SHA-512 over these ${segs.length} fields and the signature reproduces pulse #${pulse.pulseIndex}'s published outputValue.`)
        : verdictEl(
            'a1-output',
            'fail',
            'MISMATCH',
            tampered
              ? 'One flipped bit in localRandomValue changes every bit of the hash.'
              : 'With 8-byte length prefixes the bytes differ, so the hash does too. The draft text does not describe what NIST deployed.',
            r.code,
          ),
    )
  }

  sec.append(
    controls,
    out,
    expert(
      'Spec vs deployment: what the bytes actually are',
      el(
        'p',
        {},
        'NISTIR 8213 (Draft, May 2019) §4.1.2 says every non-integer field is prefixed with its length "encoded as a (serialized) 64-bit unsigned integer", and Algorithm 2 encodes external.statusCode as uint64. The deployed beacon uses 4-byte prefixes and a 4-byte external.statusCode, and outputValue hashes the raw 512-byte signature with no prefix. This lab found that by testing every combination against real pulses; the regression tests in src/nist/nist.test.ts pin it.',
      ),
      el(
        'p',
        {},
        `certificateId, likewise, is SHA-512 over the certificate's DER bytes, while the draft text describes a hash of "a Base 64 encoded PEM formatted file". Pulses were captured from beacon.nist.gov on ${NIST.fetchedAt.slice(0, 10)}.`,
      ),
    ),
  )
  host.appendChild(sec)
  render()
}
