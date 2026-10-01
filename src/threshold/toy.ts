/**
 * A small threshold-BLS beacon — the mechanism behind drand, at a size you can
 * watch. Real BLS12-381 arithmetic throughout (quicknet layout: signatures on
 * G1, keys on G2, the quicknet DST and message encoding).
 *
 * What is simplified, and labelled as such on the page: the shares come from a
 * TRUSTED DEALER who knows the group secret. drand runs a distributed key
 * generation instead, so no party ever holds it; see crypto-lab-dkg-gate.
 * Nothing below depends on how the shares were made — combining is identical.
 *
 *   share i:          sk_i = f(i), f a random degree-(t-1) polynomial, f(0) = sk
 *   partial sig:      σ_i = sk_i · H₁(m)
 *   combine any t:    σ = Σ λ_i · σ_i,   λ_i = Π_{j≠i} j / (j − i)   (mod r)
 *   group key:        pk = sk · g₂
 *
 * Because σ = sk · H₁(m) for EVERY qualifying subset, the output is unique:
 * which t signers showed up cannot change the randomness.
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { toHex } from '../core/bytes'
import { DST_G1, roundMessage, verifyRound } from '../drand/verify'

const Fr = bls.fields.Fr
const r = Fr.ORDER

type G1P = ReturnType<typeof bls.G1.hashToCurve>

export interface Dealing {
  t: number
  n: number
  /** Polynomial coefficients, a_0 = group secret. Shown only in the toy. */
  coeffs: bigint[]
  shares: bigint[]
  groupPublicKey: string
  sharePublicKeys: string[]
}

function mod(a: bigint): bigint {
  const x = a % r
  return x < 0n ? x + r : x
}

export function randomScalar(): bigint {
  const b = new Uint8Array(48)
  crypto.getRandomValues(b)
  let v = 0n
  for (const x of b) v = (v << 8n) | BigInt(x)
  return mod(v) || 1n
}

function evalPoly(coeffs: bigint[], x: bigint): bigint {
  let acc = 0n
  for (let k = coeffs.length - 1; k >= 0; k--) acc = mod(acc * x + (coeffs[k] ?? 0n))
  return acc
}

export function deal(t: number, n: number, coeffs?: bigint[]): Dealing {
  if (t < 1 || t > n) throw new Error('need 1 ≤ t ≤ n')
  const a = coeffs ?? Array.from({ length: t }, randomScalar)
  if (a.length !== t) throw new Error(`a threshold of ${t} needs ${t} coefficients`)
  const shares = Array.from({ length: n }, (_, i) => evalPoly(a, BigInt(i + 1)))
  const pk = (s: bigint) => bls.G2.Point.BASE.multiply(s).toHex()
  return { t, n, coeffs: a, shares, groupPublicKey: pk(a[0] as bigint), sharePublicKeys: shares.map(pk) }
}

export function hashRound(round: number): G1P {
  return bls.G1.hashToCurve(roundMessage('bls-unchained-g1-rfc9380', round), { DST: DST_G1 }) as G1P
}

export function partialSign(share: bigint, round: number): string {
  return hashRound(round).multiply(share).toHex()
}

/** Lagrange coefficient at x = 0 for signer index i (1-based) within `set`. */
export function lagrangeAtZero(i: number, set: number[]): bigint {
  let num = 1n
  let den = 1n
  for (const j of set) {
    if (j === i) continue
    num = mod(num * BigInt(j))
    den = mod(den * BigInt(j - i))
  }
  return mod(num * Fr.inv(den))
}

export interface Combined {
  signers: number[]
  lambdas: bigint[]
  signature: string
}

/** Interpolate in the exponent. Accepts any number of partials; only t or more give the group signature. */
export function combine(partials: Map<number, string>): Combined {
  const signers = [...partials.keys()].sort((a, b) => a - b)
  if (signers.length === 0) throw new Error('no partial signatures to combine')
  const lambdas = signers.map((i) => lagrangeAtZero(i, signers))
  let acc = bls.G1.Point.ZERO
  signers.forEach((i, k) => {
    const p = bls.G1.Point.fromHex(partials.get(i) as string)
    acc = acc.add(p.multiply(lambdas[k] as bigint))
  })
  return { signers, lambdas, signature: acc.toHex() }
}

export function verifyGroup(groupPublicKey: string, round: number, signature: string) {
  return verifyRound('bls-unchained-g1-rfc9380', groupPublicKey, round, signature)
}

/** Verify one signer's partial against that signer's public share. */
export function verifyPartial(sharePublicKey: string, round: number, partial: string): boolean {
  return verifyRound('bls-unchained-g1-rfc9380', sharePublicKey, round, partial).ok
}

export function scalarHex(s: bigint): string {
  return toHex(Fr.toBytes(s))
}
