/**
 * Act 6 — Why a threshold. A 3-of-5 BLS beacon you can operate: pick which
 * signers show up, combine their partial signatures, and see that every
 * quorum produces the same bytes (uniqueness), while two signers produce
 * nothing that verifies. Then the four properties, side by side.
 */
import { abbrev } from '../core/bytes'
import { combine, deal, partialSign, scalarHex, verifyGroup, verifyPartial, type Dealing } from '../threshold/toy'
import { button, clear, el, expert, panel } from './dom'
import { scroller, tag, verdictEl } from './verdict'

const T = 3
const N = 5
const ROUND = 1000

export function mountAct6(host: HTMLElement): void {
  const sec = panel(
    'act6',
    'Act 6 · Why a threshold makes the output unique',
    'Five signers each hold a share of one key. Any three can produce the round’s signature, and every group of three produces exactly the same one.',
  )
  sec.setAttribute('data-act', '6')
  let dealing: Dealing = deal(T, N)
  let partials: string[] = dealing.shares.map((s) => partialSign(s, ROUND))
  const chosen = new Set<number>([1, 2, 3])
  const tried: Array<{ set: string; sig: string; ok: boolean }> = []

  const signerRow = el('div', { class: 'signers', role: 'group', 'aria-label': 'Signers who show up' })
  const out = el('div', { class: 'act-out', 'aria-live': 'polite' })
  const history = el('div', {})

  function drawSigners(): void {
    clear(signerRow)
    for (let i = 1; i <= N; i++) {
      const b = el('button', {
        type: 'button',
        class: 'btn btn-toggle signer',
        'aria-pressed': String(chosen.has(i)),
        text: `Signer ${i}`,
      })
      b.addEventListener('click', () => {
        if (chosen.has(i)) chosen.delete(i)
        else chosen.add(i)
        b.setAttribute('aria-pressed', String(chosen.has(i)))
        // The verdict on screen was for the old signer set: retire it rather
        // than leave a result that no longer describes the selection.
        const had = out.querySelector('[data-check="a6-group"]') !== null
        clear(out)
        status.textContent =
          `${chosen.size} signer${chosen.size === 1 ? '' : 's'} selected.` +
          (had ? ' The previous result was for a different set and has been cleared;' : '') +
          ' combine to produce a signature.'
      })
      signerRow.appendChild(b)
    }
  }
  const status = el('p', { class: 'muted', role: 'status', 'data-claim': 'a6-status' })

  function doCombine(): void {
    clear(out)
    if (chosen.size === 0) {
      out.append(verdictEl('a6-group', 'fail', 'NO SIGNERS', 'select at least one signer.'))
      return
    }
    const m = new Map([...chosen].map((i) => [i, partials[i - 1] as string]))
    const c = combine(m)
    const v = verifyGroup(dealing.groupPublicKey, ROUND, c.signature)
    const set = c.signers.join(', ')
    tried.push({ set, sig: c.signature, ok: v.ok })
    out.append(
      el(
        'ul',
        { class: 'checks', role: 'list' },
        ...c.signers.map((i, k) =>
          el(
            'li',
            { role: 'listitem', class: 'mono' },
            tag('a6-partial', verifyPartial(dealing.sharePublicKeys[i - 1] as string, ROUND, partials[i - 1] as string), `signer ${i} partial valid`, `signer ${i} partial invalid`),
            ` λ${i} = ${abbrev(scalarHex(c.lambdas[k] as bigint), 8, 6)}`,
          ),
        ),
      ),
      el('p', {}, 'Combined signature σ = Σ λᵢ·σᵢ:'),
      el('p', { class: 'mono', 'data-claim': 'a6-signature', text: c.signature }),
      v.ok
        ? verdictEl('a6-group', 'pass', 'VALID GROUP SIGNATURE', `signers {${set}} produced a signature the group key accepts.`)
        : verdictEl(
            'a6-group',
            'fail',
            'NOT A GROUP SIGNATURE',
            `${chosen.size} of ${N} signers is below the threshold of ${T}; interpolating ${chosen.size} points gives the wrong constant term.`,
            v.code,
          ),
    )
    drawHistory()
    status.textContent = v.ok ? `Signers {${set}}: valid.` : `Signers {${set}}: rejected.`
  }

  function drawHistory(): void {
    clear(history)
    if (tried.length === 0) return
    const valid = tried.filter((t) => t.ok)
    const distinct = new Set(valid.map((t) => t.sig)).size
    history.append(
      el('h3', { text: 'Every quorum you have tried' }),
      scroller(
        'Signer sets tried',
        el(
          'table',
          { class: 'chain' },
          el('thead', {}, el('tr', {}, ...['Signers', 'Signature', 'Verifies'].map((h) => el('th', { scope: 'col', text: h })))),
          el(
            'tbody',
            {},
            ...tried.map((t) =>
              el(
                'tr',
                {},
                el('th', { scope: 'row', text: `{${t.set}}` }),
                el('td', { class: 'mono', 'data-sig': t.sig, text: abbrev(t.sig, 12, 8) }),
                el('td', {}, tag('a6-try', t.ok, 'yes', 'no')),
              ),
            ),
          ),
        ),
      ),
      el(
        'p',
        { 'data-claim': 'a6-distinct', 'data-valid': String(valid.length), 'data-distinct': String(distinct) },
        valid.length === 0
          ? 'No valid signature yet.'
          : `${valid.length} valid signature${valid.length === 1 ? '' : 's'} from ${new Set(valid.map((t) => t.set)).size} different quorum${valid.length === 1 ? '' : 's'}: ${distinct} distinct value${distinct === 1 ? '' : 's'}.`,
      ),
    )
  }

  const combineBtn = button('Combine partial signatures', doCombine)
  const gpk = el('span', { class: 'mono', 'data-claim': 'a6-gpk', 'data-full': dealing.groupPublicKey, text: abbrev(dealing.groupPublicKey, 16, 8) })
  const redeal = button('New key shares', () => {
    dealing = deal(T, N)
    gpk.textContent = abbrev(dealing.groupPublicKey, 16, 8)
    gpk.setAttribute('data-full', dealing.groupPublicKey)
    partials = dealing.shares.map((s) => partialSign(s, ROUND))
    tried.length = 0
    clear(out)
    drawHistory()
    status.textContent = 'Fresh shares dealt. Earlier signatures were for the old key and have been cleared.'
  }, 'btn-quiet')

  sec.append(
    el('p', {}, `Round ${ROUND}, quicknet layout (signatures on G1, keys on G2). Group public key: `, gpk),
    el('div', { class: 'controls' }, signerRow, el('div', { class: 'btnrow' }, combineBtn, redeal)),
    status,
    out,
    history,
    el(
      'p',
      { class: 'honesty' },
      'Simplified: a trusted dealer created these shares and briefly knew the whole key. drand uses distributed key generation, so no one ever holds it (see crypto-lab-dkg-gate). Combining and verifying work exactly the same either way.',
    ),
    expert(
      'Why every quorum agrees',
      el('p', {}, 'Each share is a point on one secret polynomial f of degree 2, and f(0) is the group secret. Lagrange interpolation at zero, applied to the partial signatures σᵢ = f(i)·H(m), gives f(0)·H(m) from any three. A BLS signature is deterministic, so that value is the only valid signature for this round. Which signers responded cannot change it, and neither can the signers themselves, short of three of them colluding to sign early.'),
    ),
  )
  host.appendChild(sec)
  drawSigners()
  doCombine()
}
