/**
 * Deployment finding, with its resolution — the 2026-09-03 key rotation and
 * the certificate that ended it, as a card beside Act 4.
 *
 * Every cell is computed from a pinned pulse by the same verifiers the acts
 * use, and both captures are shown side by side so the card states a history
 * rather than a moment: the 2026-10-01 column is the finding as filed, the
 * 2026-11-10 column is the same five checks after the repair. The dates come
 * from the fixtures and from the certificate's own notBefore.
 *
 * The wording stays deliberately narrow in both columns: origin could not be
 * verified against the certificate the pulse NAMES. It never said, and does
 * not say, that the beacon was compromised.
 */
import { parseCertificate } from '../core/der'
import { CAPTURED, certFor, certForCurrent, NIST, NIST_CURRENT } from '../nist/fixtures'
import type { Pulse } from '../nist/types'
import { checkCertificateId, checkOutputValue, checkPrecommitment, checkPreviousLink, checkSignature } from '../nist/verify'
import { el } from './dom'
import { tag } from './verdict'

/** The five checks, run over one capture's newest pulse. */
async function readState(recent: Pulse[], certOf: (p: Pulse) => string | undefined) {
  const latest = recent.at(-1) as Pulse
  const prev = recent.at(-2) as Pulse
  const pem = certOf(latest)
  const cid = pem ? checkCertificateId(latest, pem) : null
  const sig = await checkSignature(latest, pem)
  const cert = pem ? parseCertificate(pem) : null
  return {
    latest,
    cert,
    sig,
    keyBits: cert?.modulusBits ?? 0,
    checks: {
      output: checkOutputValue(latest),
      link: checkPreviousLink(prev, latest),
      precommit: checkPrecommitment(prev, latest),
      certid: { ok: cid?.ok ?? false, code: cid?.code },
      sig: { ok: sig.ok, code: sig.code },
    },
  }
}

export async function mountFinding(host: HTMLElement): Promise<void> {
  const then = await readState(NIST.recent, certFor)
  const now = await readState(NIST_CURRENT.recent, certForCurrent)
  /* Not prose: the repair's date is the replacement certificate's notBefore. */
  const fixedFrom = now.cert ? now.cert.notBefore.slice(0, 10) : CAPTURED.current

  const row = (label: string, key: keyof typeof then.checks, name: string) =>
    el(
      'tr',
      {},
      el('th', { scope: 'row', text: label }),
      el('td', {}, tag(`f-${name}`, then.checks[key].ok, 'passes', 'fails', then.checks[key].code)),
      el('td', {}, tag(`f-${name}-now`, now.checks[key].ok, 'passes', 'fails', now.checks[key].code)),
    )

  const card = el(
    'section',
    { class: 'finding', id: 'finding', 'aria-labelledby': 'finding-h', 'data-claim': 'live-finding' },
    el('h2', { id: 'finding-h', text: 'Deployment finding, and its resolution' }),
    el(
      'p',
      { class: 'meta' },
      `Observed: ${NIST.rotation.timeStamp.slice(0, 10)} (NIST pulse #${NIST.rotation.pulseIndex}, statusCode ${NIST.rotation.statusCode}). ` +
        `Filed: ${CAPTURED.historical} on pulse #${then.latest.pulseIndex}. ` +
        `Resolved: a replacement certificate valid from ${fixedFrom}, confirmed ${CAPTURED.current} on pulse #${now.latest.pulseIndex}.`,
    ),
    el(
      'table',
      { class: 'finding-table' },
      el('caption', { class: 'sr-only', text: 'The same five checks on the newest pinned NIST pulse of each capture' }),
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('td', {}),
          el('th', { scope: 'col', text: `${CAPTURED.historical} · #${then.latest.pulseIndex}` }),
          el('th', { scope: 'col', text: `${CAPTURED.current} · #${now.latest.pulseIndex}` }),
        ),
      ),
      el(
        'tbody',
        {},
        row('Pulse hash', 'output', 'output'),
        row('Hash-chain link', 'link', 'link'),
        row('Precommitment', 'precommit', 'precommit'),
        row('Named certificate', 'certid', 'certid'),
        row('Signature verification', 'sig', 'sig'),
      ),
    ),
    el(
      'p',
      {},
      el('strong', { text: 'Why: ' }),
      `on ${CAPTURED.historical} the signature was ${then.sig.sigBits} bits and the RSA modulus in the certificate the pulse named was ${then.keyBits} bits, ` +
        `so the signature could not be opened with that key at all. On ${CAPTURED.current} both are ${now.sig.sigBits} bits.`,
    ),
    el(
      'p',
      { class: 'finding-claim', 'data-claim': 'finding-claim' },
      now.checks.sig.ok && !then.checks.sig.ok
        ? `Origin verifies today against the certificate the pulse names. For the weeks between the ${NIST.rotation.timeStamp.slice(0, 10)} rotation and the certificate valid from ${fixedFrom}, it could not. Both statements are about what a verifier can check; neither was, or is, a claim that the beacon was compromised. Note what did not change: all four hash-based checks passed in both columns, so nothing but the key-size comparison would have told you.`
        : now.checks.sig.ok
          ? 'Origin verifies against the certificate the pulse names.'
          : 'Origin cannot be verified against the certificate the pulse names. That is a statement about what a verifier can check, not a claim that the beacon is compromised.',
    ),
    el(
      'p',
      { class: 'muted' },
      'A weekly job (scripts/live-check.mjs) asks beacon.nist.gov whether the repair still holds and fails when it changes. It never rewrites either capture.',
    ),
  )
  host.appendChild(card)
}
