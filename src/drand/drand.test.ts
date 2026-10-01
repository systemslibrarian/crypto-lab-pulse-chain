/**
 * Real drand rounds captured from api.drand.sh (src/fixtures/drand.json) and
 * the RFC 9380 hash-to-G1 vectors. Expected values are published ones.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import { toHex } from '../core/bytes'
import kat from '../fixtures/kat.json'
import { DRAND, type Round } from './fixtures'
import { DFAIL, DST_G1, DST_G2, randomnessOf, roundMessage, verifyRound } from './verify'

const D = DRAND.default
const Q = DRAND.quicknet

describe('KATs', () => {
  it('SHA-256("abc") (FIPS 180-4)', () => {
    expect(toHex(sha256(new TextEncoder().encode('abc')))).toBe(kat.sha256_abc)
  })

  it(`RFC 9380 J.9.1: all ${kat.hashToG1.vectors.length} hash_to_curve vectors on G1`, () => {
    for (const v of kat.hashToG1.vectors) {
      const p = bls.G1.hashToCurve(new TextEncoder().encode(v.msg), { DST: kat.hashToG1.dst }).toAffine()
      expect('0x' + p.x.toString(16).padStart(96, '0')).toBe(v.x)
      expect('0x' + p.y.toString(16).padStart(96, '0')).toBe(v.y)
    }
  })

  it('the DSTs are the ones drand-client uses', () => {
    expect(DST_G1).toBe('BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_')
    expect(DST_G2).toBe('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_')
  })
})

describe('default chain (pedersen-bls-chained)', () => {
  const all: Round[] = [...D.genesisRounds, ...D.recentRounds]
  it('chain info is the League of Entropy mainnet default chain', () => {
    expect(D.info.scheme).toBe('pedersen-bls-chained')
    expect(D.info.chain_hash).toBe('8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce')
    expect(D.info.period).toBe(30)
  })

  it(`all ${all.length} real rounds verify by pairing`, () => {
    for (const r of all) {
      const c = verifyRound('pedersen-bls-chained', D.info.public_key, r.round, r.signature, r.previous_signature)
      expect(c.ok, `round ${r.round}`).toBe(true)
    }
  })

  it('randomness = SHA-256(signature) matches what the v1 API published', () => {
    for (const r of all) expect(randomnessOf(r.signature), `round ${r.round}`).toBe(r.v1Randomness)
  })

  it('round 1 chains from the genesis seed; each later round chains from the one before', () => {
    expect((D.genesisRounds[0] as Round).previous_signature).toBe(D.info.genesis_seed)
    for (const run of [D.genesisRounds, D.recentRounds]) {
      for (let i = 1; i < run.length; i++) {
        expect((run[i] as Round).previous_signature).toBe((run[i - 1] as Round).signature)
      }
    }
  })

  it('the wrong round number fails the pairing', () => {
    const r = D.recentRounds[2] as Round
    const c = verifyRound('pedersen-bls-chained', D.info.public_key, r.round + 1, r.signature, r.previous_signature)
    expect(c.ok).toBe(false)
    expect(c.code).toBe(DFAIL.PAIRING_MISMATCH)
  })

  it('the wrong previous signature fails the pairing', () => {
    const [a, b] = D.recentRounds as [Round, Round]
    const c = verifyRound('pedersen-bls-chained', D.info.public_key, b.round, b.signature, a.previous_signature)
    expect(c.code).toBe(DFAIL.PAIRING_MISMATCH)
  })

  it('a corrupted signature is rejected as an invalid point or a mismatch, never accepted', () => {
    const r = D.recentRounds[0] as Round
    const bad = r.signature.slice(0, 40) + (r.signature[40] === '0' ? '1' : '0') + r.signature.slice(41)
    const c = verifyRound('pedersen-bls-chained', D.info.public_key, r.round, bad, r.previous_signature)
    expect(c.ok).toBe(false)
    expect([DFAIL.BAD_POINT, DFAIL.PAIRING_MISMATCH]).toContain(c.code)
  })

  it('the chained message is SHA-256(previous_signature ‖ uint64_be(round))', () => {
    const r = D.genesisRounds[0] as Round
    const m = roundMessage('pedersen-bls-chained', 1, r.previous_signature)
    const manual = sha256(new Uint8Array([...Buffer.from(D.info.genesis_seed, 'hex'), 0, 0, 0, 0, 0, 0, 0, 1]))
    expect(toHex(m)).toBe(toHex(manual))
  })
})

describe('quicknet (bls-unchained-g1-rfc9380)', () => {
  it('chain info is quicknet', () => {
    expect(Q.info.scheme).toBe('bls-unchained-g1-rfc9380')
    expect(Q.info.chain_hash).toBe('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971')
    expect(Q.info.period).toBe(3)
  })

  it(`all ${Q.rounds.length} real rounds verify, and randomness matches v1`, () => {
    for (const r of Q.rounds) {
      const c = verifyRound('bls-unchained-g1-rfc9380', Q.info.public_key, r.round, r.signature)
      expect(c.ok, `round ${r.round}`).toBe(true)
      expect(c.randomness).toBe(r.v1Randomness)
    }
  })

  it('unchained: a round verifies with no previous signature, and only for its own number', () => {
    const r = Q.rounds[1] as Round
    expect(r.previous_signature).toBeUndefined()
    expect(verifyRound('bls-unchained-g1-rfc9380', Q.info.public_key, r.round - 1, r.signature).code).toBe(
      DFAIL.PAIRING_MISMATCH,
    )
  })

  it("a default-chain signature does not verify under quicknet's scheme", () => {
    const r = D.recentRounds[0] as Round
    const c = verifyRound('bls-unchained-g1-rfc9380', Q.info.public_key, r.round, r.signature)
    expect(c.ok).toBe(false)
  })
})
