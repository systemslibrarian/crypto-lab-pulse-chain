/**
 * NIST Beacon 2.0 byte serialization — NISTIR 8213 (Draft) §4.1.2, Algorithm 2.
 *
 * Nineteen fields go into the hash that NIST signs; the output value hashes
 * those nineteen plus the signature. Integers are encoded as fixed-width
 * big-endian. Every other field (strings and hash outputs) is prefixed with
 * its own byte length.
 *
 * THE WIDTH OF THAT LENGTH PREFIX IS THE TRAP. The draft's text says it is a
 * uint64 (eq. 4: BytLen(S) = encode(len, uint64)) and that external.statusCode
 * is a uint64 (Algorithm 2, line 11). The deployed beacon does neither: its
 * pulses only reproduce with 4-byte length prefixes and a 4-byte
 * external.statusCode. That is measured, not remembered — see nist.test.ts,
 * which checks every pinned real pulse under both layouts.
 */

import { beUint, concat, fromHex, utf8 } from '../core/bytes'
import { link, type Pulse } from './types'

export interface Layout {
  name: string
  /** Bytes in the length prefix of a string / hash / signature field. */
  lengthPrefix: 4 | 8
  /** Width of external.statusCode. */
  extStatus: 4 | 8
  /** Does outputValue's preimage length-prefix the signature? */
  prefixSignatureInOutput: boolean
}

/** What beacon.nist.gov actually computes (verified against real pulses). */
export const DEPLOYED: Layout = {
  name: 'as deployed (4-byte lengths)',
  lengthPrefix: 4,
  extStatus: 4,
  prefixSignatureInOutput: false,
}

/** A literal reading of the NISTIR 8213 draft text. Reproduces no real pulse. */
export const DRAFT_TEXT: Layout = {
  name: 'NISTIR 8213 draft text (8-byte lengths)',
  lengthPrefix: 8,
  extStatus: 8,
  prefixSignatureInOutput: true,
}

export type FieldKind = 'string' | 'hash' | 'uint32' | 'uint64' | 'sig'

export interface Segment {
  field: string
  kind: FieldKind
  /** Offset of this field's first byte (its prefix, if it has one). */
  offset: number
  prefix: Uint8Array
  value: Uint8Array
}

interface FieldSpec {
  field: string
  kind: FieldKind
  get: (p: Pulse) => string | number
}

/** Algorithm 2, lines 1–19, in order. */
export const SIGNED_FIELDS: FieldSpec[] = [
  { field: 'uri', kind: 'string', get: (p) => p.uri },
  { field: 'version', kind: 'string', get: (p) => p.version },
  { field: 'cipherSuite', kind: 'uint32', get: (p) => p.cipherSuite },
  { field: 'period', kind: 'uint32', get: (p) => p.period },
  { field: 'certificateId', kind: 'hash', get: (p) => p.certificateId },
  { field: 'chainIndex', kind: 'uint64', get: (p) => p.chainIndex },
  { field: 'pulseIndex', kind: 'uint64', get: (p) => p.pulseIndex },
  { field: 'timeStamp', kind: 'string', get: (p) => p.timeStamp },
  { field: 'localRandomValue', kind: 'hash', get: (p) => p.localRandomValue },
  { field: 'external.sourceId', kind: 'hash', get: (p) => p.external.sourceId },
  // Width chosen by the layout: uint32 deployed, uint64 in the draft text.
  { field: 'external.statusCode', kind: 'uint64', get: (p) => p.external.statusCode },
  { field: 'external.value', kind: 'hash', get: (p) => p.external.value },
  { field: 'previous', kind: 'hash', get: (p) => link(p, 'previous') },
  { field: 'hour', kind: 'hash', get: (p) => link(p, 'hour') },
  { field: 'day', kind: 'hash', get: (p) => link(p, 'day') },
  { field: 'month', kind: 'hash', get: (p) => link(p, 'month') },
  { field: 'year', kind: 'hash', get: (p) => link(p, 'year') },
  { field: 'precommitmentValue', kind: 'hash', get: (p) => p.precommitmentValue },
  { field: 'statusCode', kind: 'uint32', get: (p) => p.statusCode },
]

function encodeField(spec: FieldSpec, p: Pulse, layout: Layout): { prefix: Uint8Array; value: Uint8Array } {
  const raw = spec.get(p)
  const empty = new Uint8Array(0)
  if (spec.kind === 'uint32') return { prefix: empty, value: beUint(raw as number, 4) }
  if (spec.kind === 'uint64') {
    const width = spec.field === 'external.statusCode' ? layout.extStatus : 8
    return { prefix: empty, value: beUint(raw as number, width) }
  }
  const value = spec.kind === 'string' ? utf8(raw as string) : fromHex(raw as string)
  return { prefix: beUint(value.length, layout.lengthPrefix), value }
}

/** The bytes NIST hashes and signs (Algorithm 2), as labelled segments. */
export function signedSegments(p: Pulse, layout: Layout = DEPLOYED): Segment[] {
  const out: Segment[] = []
  let offset = 0
  for (const spec of SIGNED_FIELDS) {
    const { prefix, value } = encodeField(spec, p, layout)
    const kind: FieldKind =
      spec.field === 'external.statusCode' ? (layout.extStatus === 4 ? 'uint32' : 'uint64') : spec.kind
    out.push({ field: spec.field, kind, offset, prefix, value })
    offset += prefix.length + value.length
  }
  return out
}

export function joinSegments(segs: Segment[]): Uint8Array {
  return concat(...segs.flatMap((s) => [s.prefix, s.value]))
}

/** Z in eq. (14): the signature's hash input. */
export function signatureInput(p: Pulse, layout: Layout = DEPLOYED): Uint8Array {
  return joinSegments(signedSegments(p, layout))
}

/** Z in eq. (17): the output value's hash input — the signed bytes, then the signature. */
export function outputInput(p: Pulse, layout: Layout = DEPLOYED): Uint8Array {
  const sig = fromHex(p.signatureValue)
  const sigPart = layout.prefixSignatureInOutput ? concat(beUint(sig.length, layout.lengthPrefix), sig) : sig
  return concat(signatureInput(p, layout), sigPart)
}
