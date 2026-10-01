/**
 * Act 4 — The trust boundary.
 *
 * Two lessons on one set of real pulses:
 *
 *  1. NEGATIVE CLAIM (fixture). Pulse #1925733 passes every check this page
 *     performs — and still was not unpredictable to NIST, because the engine
 *     committed to its localRandomValue a full pulse before publishing it.
 *     Verification proves integrity and origin; it cannot prove the operator
 *     did not know, or choose, the value.
 *
 *  2. A real, dated finding. Since the 2026-09-03 key rotation, pulses carry
 *     4096-bit signatures while naming a certificate with a 2048-bit key, so
 *     their origin cannot be checked at all — while every hash still passes.
 */
import { abbrev, toHex } from '../core/bytes'
import { parseCertificate } from '../core/der'
import { certFor, NIST } from '../nist/fixtures'
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

type Key = 'signed' | 'rotation' | 'latest'
const CASES: Record<Key, { text: string; pulse: Pulse; prev: Pulse }> = {
  signed: {
    text: `#${(NIST.preRotation.at(-1) as Pulse).pulseIndex} — last pulse under the old certificate`,
    pulse: NIST.preRotation.at(-1) as Pulse,
    prev: NIST.preRotation.at(-2) as Pulse,
  },
  rotation: { text: `#${NIST.rotation.pulseIndex} — the rotation pulse`, pulse: NIST.rotation, prev: NIST.preRotation.at(-1) as Pulse },
  latest: { text: `#${(NIST.recent.at(-1) as Pulse).pulseIndex} — newest pinned pulse`, pulse: NIST.recent.at(-1) as Pulse, prev: NIST.recent.at(-2) as Pulse },
}

export function mountAct4(host: HTMLElement): void {
  const sec = panel(
    'act4',
    'Act 4 · Who vouches for the pulse?',
    'Hashes show a pulse was not changed after the fact. Only the signature says NIST made it, and nothing on this page can say whether NIST knew the value first.',
  )
  sec.setAttribute('data-act', '4')
  let which: Key = 'signed'
  const out = el('div', { class: 'act-out', 'aria-live': 'polite' })
  let seq = 0

  async function render(): Promise<void> {
    const mine = ++seq
    const { pulse, prev } = CASES[which]
    const pem = certFor(pulse)
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
          `Every hash passes, but ${sig.detail}. Since the 2026-09-03 rotation, nothing here can say these pulses came from NIST.`,
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
