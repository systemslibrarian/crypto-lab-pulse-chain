/**
 * Every assertion here runs against REAL pulses captured from beacon.nist.gov
 * (src/fixtures/nist.json). Expected values are the ones NIST published —
 * never a value this suite or the source computed.
 */
import { sha512 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import { fromHex, toHex } from '../core/bytes'
import { parseCertificate } from '../core/der'
import kat from '../fixtures/kat.json'
import { certFor, NIST } from './fixtures'
import { DEPLOYED, DRAFT_TEXT, outputInput, signatureInput, signedSegments, type Layout } from './serialize'
import {
  checkCertificateId,
  checkOutputValue,
  checkPrecommitment,
  checkPreviousLink,
  checkSignature,
  FAIL,
  flipFirstByte,
  recoverSignatureBlock,
  verifySkiplist,
  withField,
} from './verify'
import { describeStatus, type Pulse } from './types'

const ALL: Pulse[] = [...NIST.preRotation, NIST.rotation, ...NIST.recent, ...NIST.skiplist.pulses]

describe('SHA-512 KAT (FIPS 180-4)', () => {
  it('hashes "abc" to the published digest', () => {
    expect(toHex(sha512(new TextEncoder().encode('abc')))).toBe(kat.sha512_abc)
  })
})

describe('serialization: the deployed layout reproduces every pinned pulse', () => {
  it(`all ${ALL.length} pinned pulses: SHA-512(serialization ‖ signature) equals the published outputValue`, () => {
    for (const p of ALL) expect(checkOutputValue(p, DEPLOYED).ok, `pulse ${p.pulseIndex}`).toBe(true)
  })

  it('REGRESSION: the NISTIR 8213 draft text (8-byte lengths) reproduces none of them', () => {
    for (const p of ALL) {
      const r = checkOutputValue(p, DRAFT_TEXT)
      expect(r.ok, `pulse ${p.pulseIndex}`).toBe(false)
      expect(r.code).toBe(FAIL.OUTPUT_MISMATCH)
    }
  })

  it('REGRESSION: each single deviation from the deployed layout breaks the hash', () => {
    const p = NIST.recent[0] as Pulse
    const variants: Layout[] = [
      { ...DEPLOYED, name: '8-byte lengths only', lengthPrefix: 8 },
      { ...DEPLOYED, name: 'uint64 ext.status only', extStatus: 8 },
      { ...DEPLOYED, name: 'prefixed signature only', prefixSignatureInOutput: true },
    ]
    for (const v of variants) expect(checkOutputValue(p, v).ok, v.name).toBe(false)
  })

  it('segments cover the serialization exactly, in Algorithm 2 order', () => {
    const p = NIST.recent[0] as Pulse
    const segs = signedSegments(p)
    expect(segs.map((s) => s.field)).toEqual([
      'uri', 'version', 'cipherSuite', 'period', 'certificateId', 'chainIndex', 'pulseIndex',
      'timeStamp', 'localRandomValue', 'external.sourceId', 'external.statusCode', 'external.value',
      'previous', 'hour', 'day', 'month', 'year', 'precommitmentValue', 'statusCode',
    ])
    let off = 0
    for (const s of segs) {
      expect(s.offset).toBe(off)
      off += s.prefix.length + s.value.length
    }
    expect(off).toBe(signatureInput(p).length)
    // 4 strings? no: uri, version, timeStamp are strings; 10 hashes of 64 bytes.
    const hashes = segs.filter((s) => s.kind === 'hash')
    expect(hashes).toHaveLength(10)
    for (const h of hashes) {
      expect(h.value).toHaveLength(64)
      expect(toHex(h.prefix)).toBe('00000040')
    }
    expect(outputInput(p).length).toBe(signatureInput(p).length + 512)
  })
})

describe('certificateId', () => {
  it('is SHA-512 over the certificate DER bytes, for both pinned certificates', () => {
    for (const p of [NIST.preRotation[0] as Pulse, NIST.recent[0] as Pulse]) {
      const c = checkCertificateId(p, certFor(p) as string)
      expect(c.ok).toBe(true)
    }
  })

  it('REGRESSION: it is NOT the hash of the PEM file the draft text describes', () => {
    const p = NIST.recent[0] as Pulse
    const c = checkCertificateId(p, certFor(p) as string)
    expect(c.pemHash).not.toBe(p.certificateId.toLowerCase())
  })

  it('parses both certificates: pre-rotation key 4096-bit, current key 2048-bit', () => {
    const old = parseCertificate(certFor(NIST.preRotation[0] as Pulse) as string)
    const cur = parseCertificate(certFor(NIST.recent[0] as Pulse) as string)
    expect(old.modulusBits).toBe(4096)
    expect(cur.modulusBits).toBe(2048)
    expect(old.exponent).toBe(65537n)
    expect(cur.subjectCN).toBe('engine.beacon.nist.gov')
    expect(cur.notBefore).toBe('2026-09-03T00:00:00Z')
  })

  it('rejects a certificate whose bytes were altered', () => {
    const p = NIST.recent[0] as Pulse
    const pem = certFor(p) as string
    // Swap one base64 character in the middle of the body.
    const i = pem.indexOf('\n', 200) + 5
    const ch = pem[i] === 'A' ? 'B' : 'A'
    const bad = pem.slice(0, i) + ch + pem.slice(i + 1)
    let ok: boolean
    try {
      ok = checkCertificateId(p, bad).ok
    } catch {
      ok = false
    }
    expect(ok).toBe(false)
  })
})

describe('RSA signature', () => {
  it('every pre-rotation pulse verifies under its certificate (WebCrypto)', async () => {
    for (const p of NIST.preRotation) {
      const s = await checkSignature(p, certFor(p))
      expect(s.ok, `pulse ${p.pulseIndex}`).toBe(true)
    }
  })

  it('the hand-rolled recovery opens to 00 01 FF…FF 00 ‖ DigestInfo(SHA-512) ‖ SHA-512(Z)', () => {
    const p = NIST.preRotation[0] as Pulse
    const rec = recoverSignatureBlock(p, parseCertificate(certFor(p) as string))
    expect(rec.wellFormed).toBe(true)
    expect(toHex(rec.block.subarray(0, 4))).toBe('0001ffff')
    expect(toHex(rec.digest)).toBe(toHex(sha512(signatureInput(p))))
  })

  it('REGRESSION: under the draft-text layout the same signature does not verify', async () => {
    const p = NIST.preRotation[0] as Pulse
    expect((await checkSignature(p, certFor(p), DRAFT_TEXT)).code).toBe(FAIL.SIG_INVALID)
  })

  it('a tampered localRandomValue fails the signature', async () => {
    const p = NIST.preRotation[2] as Pulse
    const t = withField(p, 'localRandomValue', flipFirstByte(p.localRandomValue))
    const s = await checkSignature(t, certFor(t))
    expect(s.ok).toBe(false)
    expect(s.code).toBe(FAIL.SIG_INVALID)
  })

  it('post-rotation pulses carry 4096-bit signatures naming a 2048-bit certificate', async () => {
    for (const p of [NIST.rotation, ...NIST.recent]) {
      const s = await checkSignature(p, certFor(p))
      expect(s.code, `pulse ${p.pulseIndex}`).toBe(FAIL.SIG_SIZE_MISMATCH)
      expect(s.sigBits).toBe(4096)
      expect(s.keyBits).toBe(2048)
    }
  })

  it('post-rotation pulses do not verify under the previous 4096-bit key either', async () => {
    const oldPem = certFor(NIST.preRotation[0] as Pulse) as string
    const s = await checkSignature(NIST.recent[0] as Pulse, oldPem)
    expect(s.code).toBe(FAIL.SIG_INVALID)
  })

  it('the rotation pulse self-reports a gap and a certificate change (status 6)', () => {
    expect(NIST.rotation.statusCode).toBe(6)
    expect(describeStatus(6)).toEqual([
      'this pulse follows a gap in the chain',
      'certificateId changed from the previous pulse',
    ])
    expect(NIST.rotation.certificateId).not.toBe((NIST.preRotation.at(-1) as Pulse).certificateId)
  })
})

describe('hash chain and precommitment', () => {
  const runs: Pulse[][] = [NIST.recent, [...NIST.preRotation, NIST.rotation]]
  it('every consecutive pair links (previous = prior outputValue) and opens its precommitment', () => {
    for (const run of runs) {
      for (let i = 1; i < run.length; i++) {
        const a = run[i - 1] as Pulse
        const b = run[i] as Pulse
        expect(checkPreviousLink(a, b).ok, `${a.pulseIndex}→${b.pulseIndex}`).toBe(true)
        expect(checkPrecommitment(a, b).ok, `${a.pulseIndex}→${b.pulseIndex}`).toBe(true)
      }
    }
  })

  it('the precommitment survives the 11-minute gap at the key rotation', () => {
    const last = NIST.preRotation.at(-1) as Pulse
    expect(Date.parse(NIST.rotation.timeStamp) - Date.parse(last.timeStamp)).toBe(11 * 60_000)
    expect(checkPrecommitment(last, NIST.rotation).ok).toBe(true)
  })

  it('a tampered pulse breaks its own output and the NEXT pulse\'s link', () => {
    const [a, b] = NIST.recent as [Pulse, Pulse]
    const t = withField(a, 'localRandomValue', flipFirstByte(a.localRandomValue))
    expect(checkOutputValue(t).ok).toBe(false)
    // Recomputing the forged pulse's outputValue does not help: the next pulse already committed.
    const forged = withField(t, 'outputValue', checkOutputValue(t).computed)
    expect(checkOutputValue(forged).ok).toBe(true)
    expect(checkPreviousLink(forged, b).code).toBe(FAIL.LINK_BROKEN)
    // And the tampered localRandomValue no longer opens the prior commitment.
    expect(checkPrecommitment(NIST.preRotation[0] as Pulse, NIST.preRotation[1] as Pulse).ok).toBe(true)
    const prev = { ...a, precommitmentValue: toHex(sha512(fromHex(a.localRandomValue)), true) }
    expect(checkPrecommitment(prev, t).code).toBe(FAIL.PRECOMMIT_MISMATCH)
  })
})

describe('skiplist (NISTIR 8213 Algorithm 6)', () => {
  const path = NIST.skiplist.pulses
  it('the pinned path runs from the target to the anchor and verifies', () => {
    expect((path[0] as Pulse).pulseIndex).toBe(NIST.skiplist.target)
    expect((path.at(-1) as Pulse).pulseIndex).toBe(NIST.skiplist.anchor)
    const r = verifySkiplist(path)
    expect(r.ok).toBe(true)
    expect(r.hops).toHaveLength(path.length - 1)
  })

  it('spans tens of thousands of pulses in a few dozen hops, mostly by day', () => {
    const span = NIST.skiplist.anchor - NIST.skiplist.target
    expect(span).toBe(39883)
    const r = verifySkiplist(path)
    const byDay = r.hops.filter((h) => h.via === 'day').length
    expect(byDay).toBeGreaterThan(20)
    expect(new Set(r.hops.map((h) => h.via))).toEqual(new Set(['previous', 'hour', 'day']))
  })

  it('dropping a hop breaks the path at exactly that point', () => {
    const cut = [...path.slice(0, 10), ...path.slice(11)]
    const r = verifySkiplist(cut)
    expect(r.ok).toBe(false)
    expect(r.code).toBe(FAIL.SKIPLIST_BROKEN)
    expect(r.brokenAt).toBe(9)
  })

  it('every pulse on the path also hashes to its own outputValue', () => {
    for (const p of path) expect(checkOutputValue(p).ok).toBe(true)
  })
})
