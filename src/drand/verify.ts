/**
 * drand round verification, written as the pairing equations themselves.
 *
 * Division of labour (§1 of the lab standard): @noble/curves owns field and
 * curve arithmetic, RFC 9380 hash-to-curve, and the optimal-Ate pairing. This
 * file owns what a beacon client actually decides — which bytes are signed,
 * under which domain-separation tag, on which group, and what "randomness" is.
 *
 * Two deployed schemes, opposite group layouts:
 *
 *   default  pedersen-bls-chained      pk ∈ G1 (48 B), sig ∈ G2 (96 B)
 *            m = SHA-256(previous_signature || uint64_be(round))
 *            check  e(pk, H₂(m)) == e(g₁, σ)
 *
 *   quicknet bls-unchained-g1-rfc9380  pk ∈ G2 (96 B), sig ∈ G1 (48 B)
 *            m = SHA-256(uint64_be(round))
 *            check  e(σ, g₂) == e(H₁(m), pk)
 *
 * In both, randomness = SHA-256(σ). Because BLS signatures are unique (one
 * valid σ per key and message), randomness is fixed the moment the group key
 * and round are — nobody, including the signers, gets to choose among valid
 * outputs.
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { beUint, concat, fromHex, toHex } from '../core/bytes'

/** DST for signatures on G2 — the default chain. */
export const DST_G2 = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'
/** DST for signatures on G1 — quicknet (RFC 9380 suite, "_NUL_" basic scheme). */
export const DST_G1 = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_'

export const DFAIL = {
  BAD_POINT: 'BAD_POINT',
  PAIRING_MISMATCH: 'PAIRING_MISMATCH',
  RANDOMNESS_MISMATCH: 'RANDOMNESS_MISMATCH',
  CHAIN_BROKEN: 'CHAIN_BROKEN',
} as const
export type DFailCode = (typeof DFAIL)[keyof typeof DFAIL]

export type Scheme = 'pedersen-bls-chained' | 'bls-unchained-g1-rfc9380'

export function roundMessage(scheme: Scheme, round: number, previousSignature?: string): Uint8Array {
  const r = beUint(round, 8)
  if (scheme === 'pedersen-bls-chained') {
    if (previousSignature === undefined) throw new Error('a chained round needs previous_signature')
    return sha256(concat(fromHex(previousSignature), r))
  }
  return sha256(r)
}

export function randomnessOf(signature: string): string {
  return toHex(sha256(fromHex(signature)))
}

export interface RoundCheck {
  ok: boolean
  message: string
  randomness: string
  code?: DFailCode
  detail: string
}

export function verifyRound(
  scheme: Scheme,
  publicKey: string,
  round: number,
  signature: string,
  previousSignature?: string,
): RoundCheck {
  let message = ''
  try {
    const m = roundMessage(scheme, round, previousSignature)
    message = toHex(m)
    let ok: boolean
    if (scheme === 'pedersen-bls-chained') {
      const pk = bls.G1.Point.fromHex(publicKey)
      const sig = bls.G2.Point.fromHex(signature)
      const hm = bls.G2.hashToCurve(m, { DST: DST_G2 })
      ok = bls.fields.Fp12.eql(bls.pairing(pk, hm), bls.pairing(bls.G1.Point.BASE, sig))
    } else {
      const pk = bls.G2.Point.fromHex(publicKey)
      const sig = bls.G1.Point.fromHex(signature)
      const hm = bls.G1.hashToCurve(m, { DST: DST_G1 })
      ok = bls.fields.Fp12.eql(bls.pairing(sig, bls.G2.Point.BASE), bls.pairing(hm, pk))
    }
    const randomness = randomnessOf(signature)
    return ok
      ? { ok, message, randomness, detail: 'both sides of the pairing equation agree' }
      : { ok, message, randomness, code: DFAIL.PAIRING_MISMATCH, detail: 'the two pairings differ: wrong round, wrong previous signature, or wrong key' }
  } catch (e) {
    return {
      ok: false,
      message,
      randomness: '',
      code: DFAIL.BAD_POINT,
      detail: `not a valid curve point: ${(e as Error).message}`,
    }
  }
}
