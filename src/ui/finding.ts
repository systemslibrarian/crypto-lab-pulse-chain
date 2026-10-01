/**
 * Live deployment finding — the 2026-09-03 key rotation, as a card beside
 * Act 4. Every row is computed from the newest pinned pulse by the same
 * verifiers the acts use; the dates come from the fixtures. The wording is
 * deliberately narrow: origin cannot be verified against the certificate the
 * pulse NAMES. It does not say the beacon is compromised.
 */
import { parseCertificate } from '../core/der'
import { certFor, NIST } from '../nist/fixtures'
import type { Pulse } from '../nist/types'
import { checkCertificateId, checkOutputValue, checkPrecommitment, checkPreviousLink, checkSignature } from '../nist/verify'
import { el } from './dom'
import { tag } from './verdict'

export async function mountFinding(host: HTMLElement): Promise<void> {
  const latest = NIST.recent.at(-1) as Pulse
  const prev = NIST.recent.at(-2) as Pulse
  const pem = certFor(latest)
  const own = checkOutputValue(latest)
  const link = checkPreviousLink(prev, latest)
  const pc = checkPrecommitment(prev, latest)
  const cid = pem ? checkCertificateId(latest, pem) : null
  const sig = await checkSignature(latest, pem)
  const keyBits = pem ? parseCertificate(pem).modulusBits : 0

  const row = (label: string, check: string, ok: boolean, code?: string) =>
    el('tr', {}, el('th', { scope: 'row', text: label }), el('td', {}, tag(check, ok, 'passes', 'fails', code)))

  const card = el(
    'section',
    { class: 'finding', id: 'finding', 'aria-labelledby': 'finding-h', 'data-claim': 'live-finding' },
    el('h2', { id: 'finding-h', text: 'Live deployment finding' }),
    el(
      'p',
      { class: 'meta' },
      `Observed: ${NIST.rotation.timeStamp.slice(0, 10)} (NIST pulse #${NIST.rotation.pulseIndex}, statusCode ${NIST.rotation.statusCode}). Rechecked: ${NIST.fetchedAt.slice(0, 10)} on pulse #${latest.pulseIndex}.`,
    ),
    el(
      'table',
      { class: 'finding-table' },
      el('caption', { class: 'sr-only', text: 'Checks on the newest pinned NIST pulse' }),
      el(
        'tbody',
        {},
        row('Pulse hash', 'f-output', own.ok, own.code),
        row('Hash-chain link', 'f-link', link.ok, link.code),
        row('Precommitment', 'f-precommit', pc.ok, pc.code),
        row('Named certificate', 'f-certid', cid?.ok ?? false, cid?.code),
        row('Signature verification', 'f-sig', sig.ok, sig.code),
      ),
    ),
    el(
      'p',
      {},
      el('strong', { text: 'Why: ' }),
      `the signature is ${sig.sigBits} bits; the RSA modulus in the certificate the pulse names is ${keyBits} bits.`,
    ),
    el(
      'p',
      { class: 'finding-claim', 'data-claim': 'finding-claim' },
      sig.ok
        ? 'Origin verifies against the certificate the pulse names.'
        : 'Origin cannot be verified against the certificate the pulse names. That is a statement about what a verifier can check, not a claim that the beacon is compromised.',
    ),
    el('p', { class: 'muted' }, 'A weekly job (scripts/live-check.mjs) asks beacon.nist.gov whether this still holds and fails when it changes.'),
  )
  host.appendChild(card)
}
