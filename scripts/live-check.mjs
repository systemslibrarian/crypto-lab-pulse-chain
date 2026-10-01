#!/usr/bin/env node
/**
 * Live drift check. The page states dated facts about two beacons in service,
 * from fixtures pinned on 2026-10-01. This script asks the live services
 * whether those facts still hold, using an implementation independent of
 * src/ (Buffer serializer, node:crypto, a direct noble pairing):
 *
 *   NIST  1. the newest pulse still reproduces under the deployed layout
 *            (4-byte prefixes) and still does NOT under the draft text's;
 *         2. certificateId is still SHA-512 over the certificate DER;
 *         3. whether the newest pulse's signature can be verified against the
 *            certificate it names — the page says it cannot (4096-bit
 *            signature, 2048-bit key). If NIST fixes that, Act 4 and the
 *            four-property table are stale and this check fails on purpose.
 *   drand 4. the newest default and quicknet rounds verify by pairing under
 *            the pinned group keys, and SHA-256(signature) matches v1.
 *
 * It never rewrites fixtures. A failure means a human should look, refresh
 * src/fixtures/, and update the prose that depends on them.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { createHash, verify, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'

const PINNED = JSON.parse(readFileSync(new URL('../src/fixtures/drand.json', import.meta.url), 'utf8'))
const problems = []
const note = (ok, msg) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${msg}`)
  if (!ok) problems.push(msg)
}
const get = async (url, type = 'json') => {
  const r = await fetch(url, { headers: { accept: type === 'json' ? 'application/json' : '*/*' } })
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`)
  return type === 'json' ? r.json() : r.text()
}
const sha = (alg, b) => createHash(alg).update(b).digest()

function serialize(p, w) {
  const parts = []
  const int = (n, k) => {
    const b = Buffer.alloc(k)
    if (k === 8) b.writeBigUInt64BE(BigInt(n))
    else b.writeUInt32BE(n)
    parts.push(b)
  }
  const pre = (b) => { int(b.length, w); parts.push(b) }
  const lv = (t) => p.listValues.find((l) => l.type === t).value
  pre(Buffer.from(p.uri)); pre(Buffer.from(p.version)); int(p.cipherSuite, 4); int(p.period, 4)
  pre(Buffer.from(p.certificateId, 'hex')); int(p.chainIndex, 8); int(p.pulseIndex, 8)
  pre(Buffer.from(p.timeStamp)); pre(Buffer.from(p.localRandomValue, 'hex'))
  pre(Buffer.from(p.external.sourceId, 'hex')); int(p.external.statusCode, w); pre(Buffer.from(p.external.value, 'hex'))
  for (const t of ['previous', 'hour', 'day', 'month', 'year']) pre(Buffer.from(lv(t), 'hex'))
  pre(Buffer.from(p.precommitmentValue, 'hex')); int(p.statusCode, 4)
  return Buffer.concat(parts)
}

try {
  const { pulse } = await get('https://beacon.nist.gov/beacon/2.0/pulse/last')
  const sig = Buffer.from(pulse.signatureValue, 'hex')
  const z4 = serialize(pulse, 4)
  const out4 = sha('sha512', Buffer.concat([z4, sig])).toString('hex').toUpperCase()
  const z8 = serialize(pulse, 8)
  const len8 = Buffer.alloc(8); len8.writeBigUInt64BE(BigInt(sig.length))
  const out8 = sha('sha512', Buffer.concat([z8, len8, sig])).toString('hex').toUpperCase()
  note(out4 === pulse.outputValue, `NIST #${pulse.pulseIndex}: deployed 4-byte layout reproduces outputValue`)
  note(out8 !== pulse.outputValue, `NIST #${pulse.pulseIndex}: draft-text 8-byte layout still does not`)
  const pem = await get(`https://beacon.nist.gov/beacon/2.0/certificate/${pulse.certificateId}`, 'text')
  const cert = new X509Certificate(pem)
  note(sha('sha512', cert.raw).toString('hex') === pulse.certificateId.toLowerCase(), 'NIST certificateId = SHA-512(certificate DER)')
  const keyBits = cert.publicKey.asymmetricKeyDetails?.modulusLength
  const verifies = sig.length * 8 === keyBits && verify('sha512', z4, cert.publicKey, sig)
  console.log(`     signature ${sig.length * 8} bits, certificate key ${keyBits} bits, verifies: ${verifies}`)
  note(!verifies, 'NIST newest signature still cannot be verified against its named certificate, as Act 4 states (if this FAILS, NIST fixed it: refresh the fixtures and Act 4)')
} catch (e) {
  note(false, `NIST fetch: ${e.message}`)
}

for (const [name, info, chained] of [
  ['default', PINNED.default.info, true],
  ['quicknet', PINNED.quicknet.info, false],
]) {
  try {
    const live = await get(`https://api.drand.sh/v2/chains/${info.chain_hash}/info`)
    note(live.public_key === info.public_key, `drand ${name}: group key unchanged`)
    const r = await get(`https://api.drand.sh/v2/chains/${info.chain_hash}/rounds/latest`)
    const v1 = await get(`https://api.drand.sh/${info.chain_hash}/public/${r.round}`)
    const rb = Buffer.alloc(8); rb.writeBigUInt64BE(BigInt(r.round))
    let ok
    if (chained) {
      const m = sha('sha256', Buffer.concat([Buffer.from(r.previous_signature, 'hex'), rb]))
      const h = bls.G2.hashToCurve(m, { DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_' })
      ok = bls.fields.Fp12.eql(bls.pairing(bls.G1.Point.fromHex(info.public_key), h), bls.pairing(bls.G1.Point.BASE, bls.G2.Point.fromHex(r.signature)))
    } else {
      const m = sha('sha256', rb)
      const h = bls.G1.hashToCurve(m, { DST: 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_' })
      ok = bls.fields.Fp12.eql(bls.pairing(bls.G1.Point.fromHex(r.signature), bls.G2.Point.BASE), bls.pairing(h, bls.G2.Point.fromHex(info.public_key)))
    }
    note(ok, `drand ${name} round ${r.round}: pairing verifies`)
    note(sha('sha256', Buffer.from(r.signature, 'hex')).toString('hex') === v1.randomness, `drand ${name} round ${r.round}: randomness = SHA-256(signature)`)
  } catch (e) {
    note(false, `drand ${name}: ${e.message}`)
  }
}

if (problems.length) {
  console.log(`\n${problems.length} drift finding(s). The page's dated statements may be stale.`)
  process.exitCode = 1
}
