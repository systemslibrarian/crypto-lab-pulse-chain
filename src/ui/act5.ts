/**
 * Act 5 — Verify a drand round. The same question as Act 4, answered by a
 * threshold signature: one pairing equation, computed both sides, compared.
 */
import { abbrev, toHex, beUint } from '../core/bytes'
import { DRAND, type ChainInfo, type Round } from '../drand/fixtures'
import { DST_G1, DST_G2, verifyRound } from '../drand/verify'
import { clear, el, expert, hexBlock, hexDiff, labelledSelect, panel } from './dom'
import { radios, toggle, verdictEl } from './verdict'

type ChainKey = 'default' | 'quicknet'
const CHAINS: Record<ChainKey, { info: ChainInfo; rounds: Round[]; label: string }> = {
  default: { info: DRAND.default.info, rounds: [...DRAND.default.genesisRounds, ...DRAND.default.recentRounds], label: 'default — pedersen-bls-chained, every 30 s' },
  quicknet: { info: DRAND.quicknet.info, rounds: DRAND.quicknet.rounds, label: 'quicknet — bls-unchained-g1-rfc9380, every 3 s' },
}

export function mountAct5(host: HTMLElement): void {
  const sec = panel(
    'act5',
    'Act 5 · Verify a drand round',
    'drand’s League of Entropy signs each round number with a key no single member holds. One pairing check against the group’s public key tells you the round is genuine.',
  )
  sec.setAttribute('data-act', '5')
  let chain: ChainKey = 'default'
  let wrongRound = false
  let wrongPrev = false
  const { wrap, select } = labelledSelect('a5-round', 'Round', [])
  const out = el('div', { class: 'act-out', 'aria-live': 'polite' })
  const prevToggle = toggle('Use the wrong previous signature', false, (p) => {
    wrongPrev = p
    render()
  })
  const roundToggle = toggle('Claim it is the next round', false, (p) => {
    wrongRound = p
    render()
  })

  function fillRounds(): void {
    clear(select)
    for (const r of CHAINS[chain].rounds) select.appendChild(el('option', { value: String(r.round), text: `round ${r.round.toLocaleString('en-US')}` }))
    select.value = String((CHAINS[chain].rounds.at(-1) as Round).round)
    prevToggle.disabled = chain === 'quicknet'
    if (chain === 'quicknet') {
      wrongPrev = false
      prevToggle.setAttribute('aria-pressed', 'false')
    }
  }

  function render(): void {
    clear(out)
    const { info, rounds } = CHAINS[chain]
    const idx = rounds.findIndex((r) => String(r.round) === select.value)
    const r = rounds[idx] as Round
    const chained = info.scheme === 'pedersen-bls-chained'
    const claimed = wrongRound ? r.round + 1 : r.round
    const otherPrev = rounds.find((x) => x.previous_signature && x.previous_signature !== r.previous_signature)?.previous_signature
    const prev = chained ? (wrongPrev ? otherPrev : r.previous_signature) : undefined
    const c = verifyRound(info.scheme, info.public_key, claimed, r.signature, prev)

    const steps = el('ol', { class: 'pipeline' })
    steps.append(
      el(
        'li',
        {},
        el('strong', { text: 'Message. ' }),
        chained
          ? `m = SHA-256(previous_signature ‖ uint64_be(${claimed}))`
          : `m = SHA-256(uint64_be(${claimed}))`,
        hexBlock(
          chained ? `${abbrev(prev ?? '', 16, 8)} ‖ ${toHex(beUint(claimed, 8))}` : toHex(beUint(claimed, 8)),
          'Bytes hashed into the message',
        ),
        hexBlock(c.message, 'Message m'),
      ),
      el(
        'li',
        {},
        el('strong', { text: 'Hash to curve. ' }),
        chained
          ? `H(m) is a point on G2 (RFC 9380, DST ${DST_G2}); the signature is on G2, the public key on G1.`
          : `H(m) is a point on G1 (RFC 9380, DST ${DST_G1}); the signature is on G1, the public key on G2.`,
      ),
      el(
        'li',
        {},
        el('strong', { text: 'Pairing. ' }),
        chained ? 'Check e(pk, H(m)) = e(g₁, σ).' : 'Check e(σ, g₂) = e(H(m), pk).',
        c.lhs && c.rhs ? hexDiff(c.lhs.slice(0, 48), c.rhs.slice(0, 48), 'Left side (first 24 of 576 bytes)', 'Right side (first 24 of 576 bytes)') : null,
      ),
    )
    out.append(
      steps,
      c.ok
        ? verdictEl('a5-pairing', 'pass', 'VALID ROUND', `Round ${claimed.toLocaleString('en-US')} is signed by the ${info.beacon_id} group key.`)
        : verdictEl('a5-pairing', 'fail', 'REJECTED', c.detail + '.', c.code),
    )
    if (c.ok) {
      out.append(
        el('h3', { text: 'Randomness = SHA-256(signature)' }),
        hexDiff(r.v1Randomness, c.randomness, 'Published by drand (v1 API)', 'SHA-256 of the signature, computed here'),
        r.v1Randomness === c.randomness
          ? verdictEl('a5-randomness', 'pass', 'RANDOMNESS MATCHES')
          : verdictEl('a5-randomness', 'fail', 'RANDOMNESS DIFFERS', '', 'RANDOMNESS_MISMATCH'),
      )
    }
    if (chained && idx > 0 && rounds[idx - 1]!.round === r.round - 1) {
      const ok = r.previous_signature === rounds[idx - 1]!.signature
      out.append(
        ok
          ? verdictEl('a5-continuity', 'pass', 'CHAINED', `round ${r.round}’s previous_signature is round ${r.round - 1}’s signature.`)
          : verdictEl('a5-continuity', 'fail', 'CHAIN BROKEN', '', 'CHAIN_BROKEN'),
      )
    } else if (chained && r.round === 1) {
      const ok = r.previous_signature === info.genesis_seed
      out.append(
        ok
          ? verdictEl('a5-continuity', 'pass', 'ANCHORED AT GENESIS', 'round 1’s previous_signature is the chain’s published genesis seed.')
          : verdictEl('a5-continuity', 'fail', 'NOT ANCHORED', '', 'CHAIN_BROKEN'),
      )
    }
  }

  select.addEventListener('change', render)
  sec.append(
    el(
      'div',
      { class: 'controls' },
      radios('a5-chain', 'Chain', (Object.keys(CHAINS) as ChainKey[]).map((k) => ({ value: k, text: CHAINS[k].label })), chain, (v) => {
        chain = v
        fillRounds()
        render()
      }),
      wrap,
      el('div', { class: 'ctl' }, el('span', { class: 'ctl-label', text: 'Break it yourself' }), el('div', { class: 'btnrow' }, roundToggle, prevToggle)),
    ),
    out,
    expert(
      'Chained vs unchained, and where these rounds came from',
      el('p', {}, 'The default chain signs the previous signature together with the round number, so rounds form a chain back to a genesis seed. quicknet signs only the round number, so a round’s signature can be predicted as a target before it exists. That is what makes timelock encryption possible (see crypto-lab-beacon-lock). Both are unique: one valid signature per round.'),
      el('p', {}, `Rounds were captured from api.drand.sh on ${DRAND.fetchedAt.slice(0, 10)}. The v2 API omits randomness, so each round also keeps the value the v1 endpoint published, to compare against.`),
    ),
  )
  host.appendChild(sec)
  fillRounds()
  render()
}
