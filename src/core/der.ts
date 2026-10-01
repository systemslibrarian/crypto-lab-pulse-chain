/**
 * Just enough DER to pull the pieces of an X.509 certificate this lab needs:
 * the SubjectPublicKeyInfo (for WebCrypto), the RSA modulus and exponent (for
 * the hand-rolled signature recovery), the validity window, and the subject CN.
 *
 * Strict where it matters: definite lengths only, no trailing bytes, and every
 * read is bounds-checked. It is not a general ASN.1 parser and does not
 * validate the certificate's own signature or its chain to a root — the page
 * says so where it shows a certificate.
 */

import { fromHex } from './bytes'

export interface Tlv {
  tag: number
  /** Offset of the tag byte within the outer buffer. */
  start: number
  /** Offset of the first content byte. */
  valueStart: number
  /** Offset one past the last content byte. */
  end: number
}

export function readTlv(buf: Uint8Array, at: number): Tlv {
  const tag = buf[at]
  const first = buf[at + 1]
  if (tag === undefined || first === undefined) throw new Error('DER: truncated header')
  let len = 0
  let p = at + 2
  if (first < 0x80) {
    len = first
  } else {
    const n = first & 0x7f
    if (n === 0 || n > 4) throw new Error('DER: indefinite or oversize length')
    for (let i = 0; i < n; i++) {
      const b = buf[p++]
      if (b === undefined) throw new Error('DER: truncated length')
      len = len * 256 + b
    }
  }
  const end = p + len
  if (end > buf.length) throw new Error('DER: value runs past the buffer')
  return { tag, start: at, valueStart: p, end }
}

export function children(buf: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = []
  let p = parent.valueStart
  while (p < parent.end) {
    const t = readTlv(buf, p)
    out.push(t)
    p = t.end
  }
  if (p !== parent.end) throw new Error('DER: children overrun their parent')
  return out
}

export function pemToDer(pem: string): Uint8Array {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem)
  if (!m || m[1] === undefined) throw new Error('PEM: no CERTIFICATE block')
  const b64 = m[1].replace(/\s+/g, '')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function at<T>(xs: T[], i: number, what: string): T {
  const v = xs[i]
  if (v === undefined) throw new Error(`DER: missing ${what}`)
  return v
}

function stripLeadingZero(b: Uint8Array): Uint8Array {
  let i = 0
  while (i < b.length - 1 && b[i] === 0) i++
  return b.subarray(i)
}

function decodeTime(buf: Uint8Array, t: Tlv): string {
  const s = new TextDecoder().decode(buf.subarray(t.valueStart, t.end))
  // UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ
  const full = t.tag === 0x17 ? (Number(s.slice(0, 2)) >= 50 ? '19' : '20') + s : s
  return `${full.slice(0, 4)}-${full.slice(4, 6)}-${full.slice(6, 8)}T${full.slice(8, 10)}:${full.slice(10, 12)}:${full.slice(12, 14)}Z`
}

export interface CertInfo {
  der: Uint8Array
  spki: Uint8Array
  modulus: bigint
  modulusBits: number
  exponent: bigint
  notBefore: string
  notAfter: string
  subjectCN: string
}

const OID_CN = fromHex('550403')

export function parseCertificate(pem: string): CertInfo {
  const der = pemToDer(pem)
  const cert = readTlv(der, 0)
  if (cert.end !== der.length) throw new Error('DER: trailing bytes after certificate')
  const tbs = at(children(der, cert), 0, 'tbsCertificate')
  const f = children(der, tbs)
  // Optional explicit [0] version shifts every later field by one.
  const o = at(f, 0, 'version').tag === 0xa0 ? 1 : 0
  const validity = children(der, at(f, o + 3, 'validity'))
  const subject = at(f, o + 4, 'subject')
  const spkiTlv = at(f, o + 5, 'subjectPublicKeyInfo')
  const spki = der.slice(spkiTlv.start, spkiTlv.end)
  const bitString = at(children(der, spkiTlv), 1, 'subjectPublicKey')
  // BIT STRING content: one "unused bits" byte, then DER RSAPublicKey.
  const rsaPub = readTlv(der, bitString.valueStart + 1)
  const [nT, eT] = [at(children(der, rsaPub), 0, 'modulus'), at(children(der, rsaPub), 1, 'exponent')]
  const nBytes = stripLeadingZero(der.subarray(nT.valueStart, nT.end))
  const eBytes = der.subarray(eT.valueStart, eT.end)
  let modulus = 0n
  for (const b of nBytes) modulus = (modulus << 8n) | BigInt(b)
  let exponent = 0n
  for (const b of eBytes) exponent = (exponent << 8n) | BigInt(b)

  let subjectCN = ''
  for (const rdn of children(der, subject)) {
    for (const atv of children(der, rdn)) {
      const [oid, val] = children(der, atv)
      if (!oid || !val) continue
      const oidBytes = der.subarray(oid.valueStart, oid.end)
      if (oidBytes.length === OID_CN.length && oidBytes.every((b, i) => b === OID_CN[i])) {
        subjectCN = new TextDecoder().decode(der.subarray(val.valueStart, val.end))
      }
    }
  }
  return {
    der,
    spki,
    modulus,
    modulusBits: modulus.toString(2).length,
    exponent,
    notBefore: decodeTime(der, at(validity, 0, 'notBefore')),
    notAfter: decodeTime(der, at(validity, 1, 'notAfter')),
    subjectCN,
  }
}
