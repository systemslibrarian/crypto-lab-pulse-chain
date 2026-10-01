/**
 * The four properties a randomness beacon is judged on, for both beacons.
 * Each cell that depends on a check is computed from that check on the
 * pinned data rather than written as prose, so the table cannot drift from
 * what the acts show.
 */
import { NIST, certFor } from '../nist/fixtures'
import type { Pulse } from '../nist/types'
import { checkSignature } from '../nist/verify'
import { DRAND } from '../drand/fixtures'
import { verifyRound } from '../drand/verify'
import { el, panel } from './dom'
import { scroller } from './verdict'

type Level = 'holds' | 'partial' | 'fails'
const WORD: Record<Level, string> = { holds: 'Holds', partial: 'Partly', fails: 'Does not hold' }
const ICON: Record<Level, string> = { holds: '✓', partial: '!', fails: '✗' }

function cell(prop: string, beacon: string, level: Level, text: string, act: string): HTMLElement {
  return el(
    'td',
    { 'data-property': prop, 'data-beacon': beacon, 'data-level': level },
    el('span', { class: `prop prop-${level}` }, el('span', { 'aria-hidden': 'true', text: `${ICON[level]} ` }), WORD[level]),
    el('span', { class: 'prop-text', text: ` ${text}` }),
    el('a', { href: `#${act}`, class: 'prop-act', text: `Show me why (${act === 'finding' ? 'live finding' : act.replace('act', 'Act ')})` }),
  )
}

export async function mountProperties(host: HTMLElement): Promise<void> {
  const sec = panel(
    'properties',
    'What you can and cannot check, side by side',
    'Tamper evidence plus the four properties a beacon is judged on. Each verdict comes from a check the page ran; follow its link to the experiment that shows it.',
  )
  const latest = NIST.recent.at(-1) as Pulse
  const sig = await checkSignature(latest, certFor(latest))
  const last = NIST.preRotation.at(-1) as Pulse
  const gapMin = (Date.parse(NIST.rotation.timeStamp) - Date.parse(last.timeStamp)) / 60_000 - 1
  const d = DRAND.default
  const r = d.recentRounds.at(-1)!
  const drandOk = verifyRound(d.info.scheme, d.info.public_key, r.round, r.signature, r.previous_signature).ok

  const rows: Array<[string, string, HTMLElement, HTMLElement]> = [
    [
      'tamper',
      'Tampering is detectable',
      cell('tamper', 'nist', 'holds', 'SHA-512 hash chain: one flipped bit breaks the pulse’s own hash and every later link.', 'act2'),
      cell('tamper', 'drand', 'holds', 'Each round’s BLS signature covers its round number (and, on the default chain, the previous signature).', 'act5'),
    ],
    [
      'unpredictability',
      'Unpredictability',
      cell('unpredictability', 'nist', 'partial', 'Unpredictable to outsiders until publication. Not to NIST: the engine holds each value one pulse early.', 'act4'),
      cell('unpredictability', 'drand', 'holds', 'Unless at least the threshold of League members collude, no one can compute a round before it is signed.', 'act6'),
    ],
    [
      'uniqueness',
      'Uniqueness (bias resistance)',
      cell('uniqueness', 'nist', 'fails', 'NIST chooses localRandomValue. The precommitment stops it changing its mind later, not choosing what to commit to, or skipping a pulse.', 'act4'),
      cell('uniqueness', 'drand', 'holds', 'One valid BLS signature per key and round, so every quorum yields the same randomness.', 'act6'),
    ],
    [
      'verifiability',
      'Public verifiability',
      sig.ok
        ? cell('verifiability', 'nist', 'holds', 'Hash chain plus an RSA signature that verifies against the published certificate.', 'act4')
        : cell('verifiability', 'nist', 'partial', `Hashes and links verify (Acts 1–3). The newest pinned pulse’s signature cannot be checked: ${sig.detail}.`, 'finding'),
      drandOk
        ? cell('verifiability', 'drand', 'holds', 'Anyone holding the group public key checks a round with one pairing equation.', 'act5')
        : cell('verifiability', 'drand', 'fails', 'The pinned round did not verify.', 'act5'),
    ],
    [
      'liveness',
      'Liveness',
      cell('liveness', 'nist', 'partial', `One operator. Gaps happen and are self-reported in statusCode, e.g. ${gapMin} missing pulses on ${NIST.rotation.timeStamp.slice(0, 10)}.`, 'act2'),
      cell('liveness', 'drand', 'partial', 'Needs a threshold of nodes online; below it the beacon stalls rather than emitting a weaker value.', 'act6'),
    ],
  ]

  sec.append(
    scroller(
      'Four-property comparison',
      el(
        'table',
        { class: 'props' },
        el('caption', { text: 'NIST Beacon 2.0 vs drand League of Entropy' }),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Property' }), el('th', { scope: 'col', text: 'NIST Beacon 2.0' }), el('th', { scope: 'col', text: 'drand (League of Entropy)' }))),
        el('tbody', {}, ...rows.map(([, name, a, b]) => el('tr', {}, el('th', { scope: 'row', text: name }), a, b))),
      ),
    ),
    el('p', { class: 'muted' }, 'For the same four-way split applied to a distributed VRF, see crypto-lab-icy-dvrf.'),
  )
  host.appendChild(sec)
}
