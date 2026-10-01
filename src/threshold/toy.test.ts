import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { describe, expect, it } from 'vitest'
import { combine, deal, lagrangeAtZero, partialSign, verifyGroup, verifyPartial } from './toy'

const Fr = bls.fields.Fr
// Fixed coefficients so the suite is deterministic; the page uses fresh randomness.
const D = deal(3, 5, [0x1234567890abcdefn, 0x42n, 0x7777n])
const ROUND = 1000

function partials(ids: number[]): Map<number, string> {
  return new Map(ids.map((i) => [i, partialSign(D.shares[i - 1] as bigint, ROUND)]))
}

describe('threshold BLS toy (3-of-5, real BLS12-381)', () => {
  it('Lagrange coefficients at 0 reconstruct the polynomial constant', () => {
    const set = [1, 3, 5]
    let acc = 0n
    for (const i of set) acc = Fr.add(acc, Fr.mul(lagrangeAtZero(i, set), D.shares[i - 1] as bigint))
    expect(acc).toBe(D.coeffs[0])
  })

  it('each partial verifies under its own public share', () => {
    const p = partials([1, 2, 3, 4, 5])
    for (const [i, s] of p) expect(verifyPartial(D.sharePublicKeys[i - 1] as string, ROUND, s)).toBe(true)
  })

  it('UNIQUENESS: every 3-subset combines to the byte-identical group signature', () => {
    const subsets = [[1, 2, 3], [1, 4, 5], [2, 3, 5], [3, 4, 5]]
    const sigs = subsets.map((s) => combine(partials(s)).signature)
    expect(new Set(sigs).size).toBe(1)
    expect(verifyGroup(D.groupPublicKey, ROUND, sigs[0] as string).ok).toBe(true)
  })

  it('more than t partials give the same signature too', () => {
    expect(combine(partials([1, 2, 3, 4, 5])).signature).toBe(combine(partials([1, 2, 3])).signature)
  })

  it('t-1 partials combine to a point that fails verification', () => {
    const c = combine(partials([2, 4]))
    expect(verifyGroup(D.groupPublicKey, ROUND, c.signature).ok).toBe(false)
  })

  it('a bad partial from one signer poisons the combination', () => {
    const p = partials([1, 2, 3])
    p.set(2, partialSign((D.shares[1] as bigint) + 1n, ROUND))
    expect(verifyPartial(D.sharePublicKeys[1] as string, ROUND, p.get(2) as string)).toBe(false)
    expect(verifyGroup(D.groupPublicKey, ROUND, combine(p).signature).ok).toBe(false)
  })

  it('the group signature equals sk · H(m) — what a single holder of the secret would produce', () => {
    const single = partialSign(D.coeffs[0] as bigint, ROUND)
    expect(combine(partials([2, 3, 4])).signature).toBe(single)
  })
})
