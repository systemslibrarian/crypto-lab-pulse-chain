import { NIST } from '../nist/fixtures'
import { DRAND } from '../drand/fixtures'
import { el, glossary, panel } from './dom'

export function mountIntro(host: HTMLElement): void {
  const sec = panel('intro', 'What is a randomness beacon?')
  sec.append(
    el(
      'p',
      {},
      'A randomness beacon publishes a fresh random number on a fixed schedule, for anyone to use: picking audit samples, drawing lottery winners, choosing who serves on a committee. Everyone gets the same number at the same moment, so nobody can claim they were dealt a different one.',
    ),
    el(
      'p',
      {},
      'The hard part is trust. Could the operator have known the number early, or picked one that suited them? This lab checks two beacons in service today using their real published outputs: NIST’s, run by one government lab, and drand’s, run jointly by a group of organisations called the League of Entropy. You re-run every check they allow, break each check on purpose, and find where checking stops.',
    ),
    el(
      'nav',
      { class: 'actnav', 'aria-label': 'Acts' },
      el(
        'ol',
        {},
        ...[
          ['act1', 'Recompute a NIST pulse'],
          ['act2', 'Walk the chain, then rewrite history'],
          ['act3', 'Skip from a month ago to now'],
          ['act4', 'Who vouches for the pulse?'],
          ['act5', 'Verify a drand round'],
          ['act6', 'Why a threshold makes the output unique'],
          ['properties', 'The four properties, side by side'],
        ].map(([id, t]) => el('li', {}, el('a', { href: `#${id}`, text: t }))),
      ),
    ),
    glossary([
      ['Pulse / round', 'One published output: NIST emits a pulse every 60 seconds; drand’s quicknet emits a round every 3 seconds, its default chain every 30.'],
      ['Hash chain', 'Each pulse contains the hash of the one before it, so changing an old pulse changes every pulse after it.'],
      ['Precommitment', 'Publishing the hash of a secret now and revealing the secret later. Nobody can see the value early, and the publisher can no longer change it.'],
      ['Threshold signature', 'A signature that needs any t of n key-share holders to cooperate. Fewer than t learn nothing and can produce nothing.'],
      ['Pairing', 'A map on the BLS12-381 curve that lets anyone check a BLS signature with one equation, using only the public key.'],
    ]),
    el(
      'p',
      { class: 'muted' },
      `Data: ${new Set([...NIST.recent, ...NIST.preRotation, NIST.rotation, ...NIST.skiplist.pulses].map((p) => p.pulseIndex)).size} real NIST pulses captured ${NIST.fetchedAt.slice(0, 10)}, and ${DRAND.default.genesisRounds.length + DRAND.default.recentRounds.length + DRAND.quicknet.rounds.length} real drand rounds captured ${DRAND.fetchedAt.slice(0, 10)}. The page makes no network requests.`,
    ),
  )
  host.appendChild(sec)
}
