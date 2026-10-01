/** Typed access to the pinned NIST pulses (src/fixtures/nist.json). */
import raw from '../fixtures/nist.json'
import type { Pulse } from './types'

interface NistFixtures {
  fetchedAt: string
  certificates: Record<string, string>
  recent: Pulse[]
  preRotation: Pulse[]
  rotation: Pulse
  skiplist: { target: number; anchor: number; pulses: Pulse[] }
}

export const NIST = raw as unknown as NistFixtures

export function certFor(p: Pulse): string | undefined {
  return NIST.certificates[p.certificateId.toLowerCase()]
}
