/**
 * Every check a NIST Beacon 2.0 pulse supports, each reported independently.
 *
 * Hashes: SHA-512 from @noble/hashes (synchronous, so the UI can recompute on
 * every keystroke). Signature: WebCrypto RSASSA-PKCS1-v1_5 / SHA-512 decides
 * the verdict; a hand-rolled modular exponentiation recovers the padded block
 * so the page can SHOW what the signature opens to rather than assert it.
 */

import { sha512 } from '@noble/hashes/sha2.js'
import { bytesEqual, fromHex, i2osp, modPow, os2ip, toHex } from '../core/bytes'
import { parseCertificate, type CertInfo } from '../core/der'
import { DEPLOYED, outputInput, signatureInput, type Layout } from './serialize'
import { LINK_TYPES, link, type LinkType, type Pulse } from './types'

/** Failure codes. Each is surfaced verbatim in the UI and asserted in e2e/claims.spec.ts. */
export const FAIL = {
  OUTPUT_MISMATCH: 'OUTPUT_MISMATCH',
  CERT_ID_MISMATCH: 'CERT_ID_MISMATCH',
  CERT_UNKNOWN: 'CERT_UNKNOWN',
  SIG_SIZE_MISMATCH: 'SIG_SIZE_MISMATCH',
  SIG_INVALID: 'SIG_INVALID',
  PRECOMMIT_MISMATCH: 'PRECOMMIT_MISMATCH',
  LINK_BROKEN: 'LINK_BROKEN',
  SKIPLIST_BROKEN: 'SKIPLIST_BROKEN',
} as const
export type FailCode = (typeof FAIL)[keyof typeof FAIL]

export interface OutputCheck {
  ok: boolean
  published: string
  computed: string
  code?: FailCode
}

export function checkOutputValue(p: Pulse, layout: Layout = DEPLOYED): OutputCheck {
  const computed = toHex(sha512(outputInput(p, layout)), true)
  const published = p.outputValue.toUpperCase()
  const ok = computed === published
  return ok ? { ok, published, computed } : { ok, published, computed, code: FAIL.OUTPUT_MISMATCH }
}

export interface CertIdCheck {
  ok: boolean
  /** SHA-512 over the certificate's DER bytes — what NIST actually hashes. */
  derHash: string
  /** SHA-512 over the PEM file's bytes — what the draft's §4.8.2 text describes. */
  pemHash: string
  code?: FailCode
}

export function checkCertificateId(p: Pulse, pem: string): CertIdCheck {
  const cert = parseCertificate(pem)
  const derHash = toHex(sha512(cert.der))
  const pemHash = toHex(sha512(new TextEncoder().encode(pem)))
  const ok = derHash === p.certificateId.toLowerCase()
  return ok ? { ok, derHash, pemHash } : { ok, derHash, pemHash, code: FAIL.CERT_ID_MISMATCH }
}

/** DER DigestInfo prefix for SHA-512 (RFC 8017 §9.2, note 1). */
export const SHA512_DIGEST_INFO = fromHex('3051300d060960864801650304020305000440')

export interface Recovered {
  /** s^e mod n, as k bytes. */
  block: Uint8Array
  /** Does it have the 00 01 FF..FF 00 || DigestInfo || H shape for H = SHA-512(Z)? */
  wellFormed: boolean
  digest: Uint8Array
  expectedDigest: Uint8Array
}

/** Open the signature with the public key by hand — RSA "encryption" of s. */
export function recoverSignatureBlock(p: Pulse, cert: CertInfo, layout: Layout = DEPLOYED): Recovered {
  const k = Math.ceil(cert.modulusBits / 8)
  const s = os2ip(fromHex(p.signatureValue))
  const expectedDigest = sha512(signatureInput(p, layout))
  if (s >= cert.modulus) {
    return { block: new Uint8Array(0), wellFormed: false, digest: new Uint8Array(0), expectedDigest }
  }
  const block = i2osp(modPow(s, cert.exponent, cert.modulus), k)
  const tLen = SHA512_DIGEST_INFO.length + 64
  const psLen = k - 3 - tLen
  let wellFormed = block[0] === 0x00 && block[1] === 0x01 && psLen >= 8 && block[2 + psLen] === 0x00
  for (let i = 2; wellFormed && i < 2 + psLen; i++) if (block[i] !== 0xff) wellFormed = false
  const info = block.subarray(k - tLen, k - 64)
  const digest = block.slice(k - 64)
  wellFormed = wellFormed && bytesEqual(info, SHA512_DIGEST_INFO) && bytesEqual(digest, expectedDigest)
  return { block, wellFormed, digest, expectedDigest }
}

export interface SignatureCheck {
  ok: boolean
  sigBits: number
  keyBits: number
  code?: FailCode
  detail: string
}

export async function checkSignature(p: Pulse, pem: string | undefined, layout: Layout = DEPLOYED): Promise<SignatureCheck> {
  const sig = fromHex(p.signatureValue)
  const sigBits = sig.length * 8
  if (pem === undefined) {
    return { ok: false, sigBits, keyBits: 0, code: FAIL.CERT_UNKNOWN, detail: 'no certificate is pinned for this certificateId' }
  }
  const cert = parseCertificate(pem)
  const keyBits = cert.modulusBits
  if (sig.length !== Math.ceil(keyBits / 8)) {
    return {
      ok: false,
      sigBits,
      keyBits,
      code: FAIL.SIG_SIZE_MISMATCH,
      detail: `a ${sigBits}-bit signature cannot come from the ${keyBits}-bit key in the certificate this pulse names`,
    }
  }
  const key = await crypto.subtle.importKey(
    'spki',
    cert.spki as BufferSource,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
    false,
    ['verify'],
  )
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig as BufferSource, signatureInput(p, layout) as BufferSource)
  return ok
    ? { ok, sigBits, keyBits, detail: `RSASSA-PKCS1-v1_5 / SHA-512 verifies under the ${keyBits}-bit certificate key` }
    : { ok, sigBits, keyBits, code: FAIL.SIG_INVALID, detail: 'the signature does not verify over these bytes' }
}

export interface PrecommitCheck {
  ok: boolean
  committed: string
  opened: string
  code?: FailCode
}

/** preCom[i-1] = SHA-512(localRandomValue[i]) — NISTIR 8213 §4.7. */
export function checkPrecommitment(prev: Pulse, cur: Pulse): PrecommitCheck {
  const opened = toHex(sha512(fromHex(cur.localRandomValue)), true)
  const committed = prev.precommitmentValue.toUpperCase()
  const ok = opened === committed
  return ok ? { ok, committed, opened } : { ok, committed, opened, code: FAIL.PRECOMMIT_MISMATCH }
}

export interface LinkCheck {
  ok: boolean
  code?: FailCode
}

/** cur.previous = prev.outputValue — the hash chain. */
export function checkPreviousLink(prev: Pulse, cur: Pulse): LinkCheck {
  const ok = link(cur, 'previous').toUpperCase() === prev.outputValue.toUpperCase()
  return ok ? { ok } : { ok, code: FAIL.LINK_BROKEN }
}

export interface Hop {
  from: number
  to: number
  /** Which linking field of `to` carries `from`'s outputValue, if any. */
  via: LinkType | null
}

export interface SkiplistCheck {
  ok: boolean
  hops: Hop[]
  /** Index into hops of the first broken hop. */
  brokenAt: number | null
  code?: FailCode
}

/**
 * NISTIR 8213 Algorithm 6. Each pulse must carry the previous entry's
 * outputValue in one of its linking fields. Note what it does NOT check: that
 * each pulse's outputValue is its own hash. A caller who wants the chain to
 * bind content must also run checkOutputValue on every entry — the lab does,
 * and shows the two results separately.
 */
export function verifySkiplist(path: Pulse[]): SkiplistCheck {
  const hops: Hop[] = []
  let brokenAt: number | null = null
  for (let i = 1; i < path.length; i++) {
    const q = path[i - 1] as Pulse
    const cur = path[i] as Pulse
    const via = LINK_TYPES.find((t) => link(cur, t).toUpperCase() === q.outputValue.toUpperCase()) ?? null
    hops.push({ from: q.pulseIndex, to: cur.pulseIndex, via })
    if (via === null && brokenAt === null) brokenAt = hops.length - 1
  }
  return brokenAt === null ? { ok: true, hops, brokenAt } : { ok: false, hops, brokenAt, code: FAIL.SKIPLIST_BROKEN }
}

/** A deep copy with one field edited — every tamper in the UI goes through here. */
export function withField(p: Pulse, field: string, value: string): Pulse {
  const c: Pulse = JSON.parse(JSON.stringify(p))
  if (field === 'localRandomValue') c.localRandomValue = value
  else if (field === 'timeStamp') c.timeStamp = value
  else if (field === 'precommitmentValue') c.precommitmentValue = value
  else if (field === 'outputValue') c.outputValue = value
  else if (field === 'signatureValue') c.signatureValue = value
  else if ((LINK_TYPES as readonly string[]).includes(field)) {
    const l = c.listValues.find((x) => x.type === field)
    if (l) l.value = value
  } else throw new Error(`withField: ${field} is not editable`)
  return c
}

/** Flip the low bit of the first byte of a hex string. */
export function flipFirstByte(hex: string): string {
  const b = fromHex(hex)
  b[0] = (b[0] ?? 0) ^ 0x01
  const out = toHex(b)
  return hex === hex.toUpperCase() ? out.toUpperCase() : out
}
