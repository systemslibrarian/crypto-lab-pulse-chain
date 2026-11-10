/**
 * Act 4 — The trust boundary, and a repair with a date on it.
 *
 * Two lessons on real pulses from two pinned captures:
 *
 *  1. NEGATIVE CLAIM (fixture). Pulse #1925733 passes every check this page
 *     performs — and still was not unpredictable to NIST, because the engine
 *     committed to its localRandomValue a full pulse before publishing it.
 *     Verification proves integrity and origin; it cannot prove the operator
 *     did not know, or choose, the value. This lesson has no expiry date.
 *
 *  2. A dated history. For some weeks NIST's beacon signature could not be
 *     verified against the certificate the pulses named, and then it could:
 *
 *       2026-09-03  rotation pulse #1925734. The engine begins naming a
 *                   certificate with a 2048-bit RSA key while continuing to
 *                   emit 4096-bit signatures. A 4096-bit signature cannot be
 *                   opened with a 2048-bit modulus, so origin stops being
 *                   checkable — while every hash keeps passing.
 *       2026-10-01  captured in src/fixtures/nist.json. Pulse #1965616 still
 *                   shows the mismatch, a month on.
 *       2026-10-21  the notBefore of a replacement certificate that carries a
 *                   4096-bit key again (same CN, same 2027-03-20 expiry).
 *       2026-11-10  captured in src/fixtures/nist-current.json. Pulse
 *                   #2021249 verifies: 4096-bit signature, 4096-bit key.
 *
 *     Both captures are kept and both are selectable below, because "it
 *     verifies now" is only half the lesson. The other half is that a beacon
 *     in service published pulses nobody outside NIST could attribute to
 *     NIST, every hash check passed throughout, and nothing on this page
 *     would have told you unless it checked the key size against the
 *     signature. The dates come from the fixtures and the certificates, not
 *     from prose: FIXED_FROM below is read out of the certificate's DER.
 */
import { abbrev, toHex } from '../core/bytes'
import { parseCertificate } from '../core/der'
import { CAPTURED, certFor, certForCurrent, NIST, NIST_CURRENT } from '../nist/fixtures'
import { describeStatus, type Pulse } from '../nist/types'
import {
  checkCertificateId,
  checkOutputValue,
  checkPrecommitment,
  checkSignature,
  recoverSignatureBlock,
} from '../nist/verify'
import { clear, el, expert, hexBlock, panel } from './dom'
import { radios, verdictEl } from './verdict'

/** The negative claim, verbatim. Asserted by e2e/claims.spec.ts. */
export const NEGATIVE_CLAIM =
  'Passing every check does not show this value was unpredictable to NIST. The beacon engine generated localRandomValue and published a commitment to it one pulse earlier, so it held the value before anyone else could see it. These checks prove integrity and origin, not that the operator did not know or choose the output.'

type Key = 'signed' | 'rotation' | 'latest' | 'current'
const CASES: Record<Key, { text: string; pulse: Pulse; prev: Pulse; cert: (p: Pulse) => string | undefined }> = {
  signed: {
    text: `#${(NIST.preRotation.at(-1) as Pulse).pulseIndex} — 2026-09-03, last pulse under the old certificate`,
    pulse: NIST.preRotation.at(-1) as Pulse,
    prev: NIST.preRotation.at(-2) as Pulse,
    cert: certFor,
  },
  rotation: {
    text: `#${NIST.rotation.pulseIndex} — 2026-09-03, the rotation pulse`,
    pulse: NIST.rotation,
    prev: NIST.preRotation.at(-1) as Pulse,
    cert: certFor,
  },
  latest: {
    text: `#${(NIST.recent.at(-1) as Pulse).pulseIndex} — ${CAPTURED.historical}, a month into the mismatch`,
    pulse: NIST.recent.at(-1) as Pulse,
    prev: NIST.recent.at(-2) as Pulse,
    cert: certFor,
  },
  current: {
    text: `#${(NIST_CURRENT.recent.at(-1) as Pulse).pulseIndex} — ${CAPTURED.current}, after the 4096-bit certificate`,
    pulse: NIST_CURRENT.recent.at(-1) as Pulse,
    prev: NIST_CURRENT.recent.at(-2) as Pulse,
    cert: certForCurrent,
  },
}

/** Read out of the replacement certificate's DER, so the date cannot drift. */
const FIXED_FROM = ((): string => {
  const pem = certForCurrent(NIST_CURRENT.recent.at(-1) as Pulse)
  return pem ? parseCertificate(pem).notBefore.slice(0, 10) : CAPTURED.current
})()

export function mountAct4(host: HTMLElement): void {
  const sec = panel(
    'act4',
    'Act 4 · Who vouches for the pulse?',
    `Hashes show a pulse was not changed after the fact. Only the signature says NIST made it — and for several weeks in 2026 it could not, because the pulses named a certificate whose key was too small to have produced their signatures. Both states are pinned here: pick ${CAPTURED.historical} to see origin unverifiable, ${CAPTURED.current} to see it verify again. Neither state can say whether NIST knew the value first.`,
  )
  sec.setAttribute('data-act', '4')
  let which: Key = 'signed'
  const out = el('div', { class: 'act-out', 'aria-live': 'polite' })
  let seq = 0

  async function render(): Promise<void> {
    const mine = ++seq
    const { pulse, prev, cert: certOf } = CASES[which]
    const pem = certOf(pulse)
    const sig = await checkSignature(pulse, pem)
    if (mine !== seq) return
    clear(out)
    const own = checkOutputValue(pulse)
    const cid = pem ? checkCertificateId(pulse, pem) : null
    const pc = checkPrecommitment(prev, pulse)
    const cert = pem ? parseCertificate(pem) : null
    const allPass = own.ok && (cid?.ok ?? false) && sig.ok && pc.ok

    const checks = el(
      'ul',
      { class: 'checks', role: 'list' },
      el('li', { role: 'listitem' }, own.ok
        ? verdictEl('a4-output', 'pass', 'Output value', 'SHA-512 of the pulse reproduces its outputValue.')
        : verdictEl('a4-output', 'fail', 'Output value', 'does not reproduce.', own.code)),
      el('li', { role: 'listitem' }, cid?.ok
        ? verdictEl('a4-certid', 'pass', 'Certificate ID', 'SHA-512 of the pinned certificate’s DER bytes equals certificateId.')
        : verdictEl('a4-certid', 'fail', 'Certificate ID', 'does not match the pinned certificate.', cid?.code)),
      el('li', { role: 'listitem' }, sig.ok
        ? verdictEl('a4-sig', 'pass', 'RSA signature', sig.detail + '.')
        : verdictEl('a4-sig', 'fail', 'RSA signature', sig.detail + '.', sig.code)),
      el('li', { role: 'listitem' }, pc.ok
        ? verdictEl('a4-precommit', 'pass', 'Precommitment', `pulse #${prev.pulseIndex} committed to this localRandomValue at ${prev.timeStamp.slice(11, 16)} UTC.`)
        : verdictEl('a4-precommit', 'fail', 'Precommitment', 'does not open.', pc.code)),
    )

    out.append(
      el('p', { class: 'meta' }, `statusCode ${pulse.statusCode}: ${describeStatus(pulse.statusCode).join('; ')}.`),
      checks,
    )

    if (allPass) {
      out.append(
        el(
          'div',
          { class: 'fixture', 'data-fixture': 'operator-knows' },
          verdictEl('a4-headline', 'warn', 'VERIFIED — AND KNOWN TO THE OPERATOR FIRST'),
          el(
            'ol',
            { class: 'timeline' },
            el('li', {}, el('strong', { text: `${prev.timeStamp.slice(11, 16)} UTC` }), ` NIST publishes pulse #${prev.pulseIndex}, whose precommitmentValue ${abbrev(prev.precommitmentValue, 10, 6)} is SHA-512 of the value below. The engine already holds that value.`),
            el('li', {}, el('strong', { text: `${pulse.timeStamp.slice(11, 16)} UTC` }), ` Pulse #${pulse.pulseIndex} reveals localRandomValue ${abbrev(pulse.localRandomValue, 10, 6)}, and every check above passes.`),
          ),
          el('p', { class: 'negative-claim', 'data-claim': 'negative-claim' }, NEGATIVE_CLAIM),
          el('p', { class: 'muted' }, 'There is no failure code for this. No check could raise one: the absence of a code is the point.'),
        ),
      )
    } else {
      out.append(
        verdictEl(
          'a4-headline',
          'fail',
          'HASHES CHECK — ORIGIN CANNOT BE CHECKED',
          `Every hash passes, but ${sig.detail}. From the 2026-09-03 rotation until the replacement certificate valid from ${FIXED_FROM}, nothing on this page could say these pulses came from NIST. Select the ${CAPTURED.current} pulse to see the same four checks after the repair.`,
          sig.code,
        ),
      )
    }

    if (cert) {
      const rec = recoverSignatureBlock(pulse, cert)
      out.append(
        expert(
          'Open the signature by hand',
          el('p', {}, `Certificate: CN=${cert.subjectCN}, ${cert.modulusBits}-bit RSA, e = ${cert.exponent}, valid ${cert.notBefore.slice(0, 10)} to ${cert.notAfter.slice(0, 10)}. Signature: ${sig.sigBits} bits.`),
          rec.block.length
            ? el(
                'div',
                {},
                el('p', {}, 'signature^e mod n — a valid PKCS #1 v1.5 signature opens to 00 01 FF…FF 00, the SHA-512 DigestInfo, then SHA-512 of the nineteen serialized fields:'),
                hexBlock(`${toHex(rec.block.subarray(0, 8))} … ${toHex(rec.block.subarray(rec.block.length - 83, rec.block.length - 64))} ${toHex(rec.digest)}`, 'Recovered signature block'),
                el('p', {}, 'SHA-512 of the serialized fields, computed here:'),
                hexBlock(toHex(rec.expectedDigest), 'Expected digest'),
                rec.wellFormed
                  ? verdictEl('a4-recover', 'pass', 'Opens correctly', 'the block has the PKCS #1 v1.5 shape and its last 64 bytes equal the digest.')
                  : verdictEl('a4-recover', 'fail', 'Does not open', 'the recovered block is not a PKCS #1 v1.5 encoding of this digest.'),
              )
            : el('p', {}, `The signature, read as a number, is larger than this certificate’s ${cert.modulusBits}-bit modulus, so it cannot even be opened with this key.`),
          el('p', { class: 'muted' }, 'The lab checks the certificate’s hash against certificateId. It does not validate the certificate’s own signature or its chain to a certificate authority.'),
        ),
      )
    }
  }

  sec.append(
    el(
      'div',
      { class: 'controls' },
      radios(
        'a4-pulse',
        'Pulse',
        (Object.keys(CASES) as Key[]).map((k) => ({ value: k, text: CASES[k].text })),
        which,
        (v) => {
          which = v
          void render()
        },
      ),
    ),
    out,
  )
  host.appendChild(sec)
  void render()
}
