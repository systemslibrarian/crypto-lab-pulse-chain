/** A NIST Randomness Beacon 2.0 pulse, exactly as the JSON API serves it. */
export interface ListValue {
  uri: string
  type: 'previous' | 'hour' | 'day' | 'month' | 'year'
  value: string
}

export interface Pulse {
  uri: string
  version: string
  cipherSuite: number
  period: number
  certificateId: string
  chainIndex: number
  pulseIndex: number
  timeStamp: string
  localRandomValue: string
  external: { sourceId: string; statusCode: number; value: string }
  listValues: ListValue[]
  precommitmentValue: string
  statusCode: number
  signatureValue: string
  outputValue: string
}

export const LINK_TYPES = ['previous', 'hour', 'day', 'month', 'year'] as const
export type LinkType = (typeof LINK_TYPES)[number]

export function link(p: Pulse, type: LinkType): string {
  const v = p.listValues.find((l) => l.type === type)
  if (!v) throw new Error(`pulse ${p.pulseIndex} has no ${type} link`)
  return v.value
}

/** statusCode bit flags, NISTIR 8213 Table 5. */
export const STATUS_FLAGS: { bit: number; meaning: string }[] = [
  { bit: 1, meaning: 'localRandomValue does not open the previous precommitment' },
  { bit: 2, meaning: 'this pulse follows a gap in the chain' },
  { bit: 4, meaning: 'certificateId changed from the previous pulse' },
  { bit: 8, meaning: 'last pulse in the chain' },
]

export function describeStatus(code: number): string[] {
  if (code === 0) return ['normal transition from the previous pulse']
  return STATUS_FLAGS.filter((f) => (code & f.bit) !== 0).map((f) => f.meaning)
}
