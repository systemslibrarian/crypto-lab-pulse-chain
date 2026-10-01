/** Typed access to the pinned drand rounds (src/fixtures/drand.json). */
import raw from '../fixtures/drand.json'
import type { Scheme } from './verify'

export interface ChainInfo {
  public_key: string
  period: number
  genesis_time: number
  genesis_seed: string
  chain_hash: string
  scheme: Scheme
  beacon_id: string
}

export interface Round {
  round: number
  signature: string
  previous_signature?: string
  v1Randomness: string
}

interface DrandFixtures {
  fetchedAt: string
  default: { info: ChainInfo; genesisRounds: Round[]; recentRounds: Round[] }
  quicknet: { info: ChainInfo; rounds: Round[] }
}

export const DRAND = raw as unknown as DrandFixtures
