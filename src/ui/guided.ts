/**
 * Guided mode — the 90-second version of the whole lab, above the six acts.
 *
 *   1. VERIFY  a real NIST pulse: five real checks, all green.
 *   2. BREAK   it: one flipped bit, and the checks that depend on it fail.
 *   3. PUNCHLINE: the untouched pulse again — everything passes, and NIST
 *              still held the value a pulse before anyone else.
 *   4. CONTRAST: a threshold signer set, where every quorum yields the same
 *              bytes and too few signers yield nothing.
 *
 * Every verdict here is computed by the same verifiers the acts use; nothing
 * is scripted to come out green. Steps unlock in order (progressive
 * disclosure); the acts below remain the expert route.
 */
import { abbrev } from '../core/bytes'
import { certFor, NIST } from '../nist/fixtures'
import type { Pulse } from '../nist/types'
import {
  checkCertificateId,
  checkOutputValue,
  checkPrecommitment,
  checkPreviousLink,
  checkSignature,
  flipFirstByte,
  withField,
} from '../nist/verify'
import { combine, deal, partialSign, scalarHex, verifyGroup, verifyPartial } from '../threshold/toy'
import { button, clear, el, expert } from './dom'
import { verdictEl } from './verdict'

const PULSE = NIST.preRotation.at(-1) as Pulse
const PREV = NIST.preRotation.at(-2) as Pulse
const T = 3
const NAMES = ['A', 'B', 'C', 'D', 'E'] as const
const ROUND = 1000

interface CheckRow {
  check: string
  label: string
  ok: boolean
  code: string | undefined
  detail: string
}

async function runChecks(p: Pulse): Promise<CheckRow[]> {
  const own = checkOutputValue(p)
  const link = checkPreviousLink(PREV, p)
  const pc = checkPrecommitment(PREV, p)
  const pem = certFor(p)
  const cid = pem ? checkCertificateId(p, pem) : null
  const sig = await checkSignature(p, pem)
  return [
    { check: 'g-output', label: 'SHA-512 output', ok: own.ok, code: own.code, detail: own.ok ? 'the pulse hashes to its published outputValue' : 'the pulse no longer hashes to its published outputValue' },
    { check: 'g-link', label: 'Previous-pulse link', ok: link.ok, code: link.code, detail: link.ok ? `it carries pulse #${PREV.pulseIndex}’s outputValue` : 'it does not carry the previous outputValue' },
    { check: 'g-precommit', label: 'Precommitment', ok: pc.ok, code: pc.code, detail: pc.ok ? `it opens the commitment pulse #${PREV.pulseIndex} published` : 'it does not open the commitment the previous pulse published' },
    { check: 'g-certid', label: 'Certificate ID', ok: cid?.ok ?? false, code: cid?.code, detail: cid?.ok ? 'it names the pinned NIST certificate' : 'it does not name the pinned certificate' },
    { check: 'g-sig', label: 'RSA signature', ok: sig.ok, code: sig.code, detail: sig.ok ? 'NIST’s key signed exactly these bytes' : 'NIST’s signature does not cover these bytes' },
  ]
}

function checkList(rows: CheckRow[]): HTMLElement {
  return el(
    'ul',
    { class: 'checks guided-checks', role: 'list' },
    ...rows.map((r) => el('li', { role: 'listitem' }, verdictEl(r.check, r.ok ? 'pass' : 'fail', r.label, `— ${r.detail}.`, r.ok ? undefined : r.code))),
  )
}

function step(n: number, title: string): HTMLElement {
  const s = el('section', { class: 'gstep', id: `guided-${n}`, 'aria-labelledby': `guided-${n}-h`, 'data-step': String(n) })
  s.appendChild(el('h3', { id: `guided-${n}-h` }, el('span', { class: 'gstep-n', text: `${n}` }), ` ${title}`))
  return s
}

function choice(question: string, options: Array<[string, string]>, onPick: (reply: string) => void): HTMLElement {
  const wrap = el('div', { class: 'gchoice', role: 'group', 'aria-label': question }, el('p', { class: 'gquestion', text: question }))
  const row = el('div', { class: 'btnrow' })
  const reply = el('p', { class: 'greply', role: 'status' })
  for (const [label, response] of options) {
    row.appendChild(
      button(label, () => {
        for (const b of row.querySelectorAll('button')) b.disabled = true
        reply.textContent = response
        onPick(response)
      }, 'btn-quiet'),
    )
  }
  wrap.append(row, reply)
  return wrap
}

export function mountGuided(host: HTMLElement): void {
  const sec = el('section', { class: 'panel guided', id: 'guided', 'aria-labelledby': 'guided-h' })
  sec.append(
    el('h2', { id: 'guided-h', text: 'Can a random number be cryptographically verified — and still not be fair?' }),
    el(
      'p',
      { class: 'panel-lede' },
      'We’ll verify a real NIST beacon pulse. Every check will pass. Then we’ll show you what those checks cannot prove. About ninety seconds; the six acts below hold every byte and equation.',
    ),
  )
  const flow = el('div', { class: 'gflow' })
  const startRow = el('div', { class: 'btnrow' })
  const start = button('Start the experiment', () => {
    start.disabled = true
    void stepVerify()
  })
  startRow.append(start, el('a', { class: 'btn btn-quiet btn-link', href: '#act1', text: 'Explore all six acts' }))
  sec.append(startRow, flow)
  host.appendChild(sec)

  // ── 1. Verify ─────────────────────────────────────────────────────────────
  async function stepVerify(): Promise<void> {
    const s = step(1, 'Verify it')
    s.append(
      el(
        'p',
        {},
        `Pulse #${PULSE.pulseIndex}, published by NIST at ${PULSE.timeStamp.slice(11, 16)} UTC on ${PULSE.timeStamp.slice(0, 10)}. Its random output: `,
        el('span', { class: 'mono', text: abbrev(PULSE.outputValue, 16, 8) }),
      ),
    )
    const out = el('div', { 'aria-live': 'polite' })
    const go = button('Verify this pulse', async () => {
      go.disabled = true
      const rows = await runChecks(PULSE)
      out.append(checkList(rows))
      const all = rows.every((r) => r.ok)
      out.append(verdictEl('g-verified', all ? 'pass' : 'fail', all ? 'VERIFIED' : 'NOT VERIFIED', all ? 'every check passes.' : ''))
      out.append(
        choice('So this random number is trustworthy, right?', [
          ['Yes', 'It certainly hasn’t been tampered with. Let’s test that claim first.'],
          ['Not necessarily', 'Good instinct. First, let’s see what these checks are good at.'],
        ], () => stepBreak()),
      )
    })
    s.append(go, out)
    flow.appendChild(s)
    s.scrollIntoView({ block: 'start' })
  }

  // ── 2. Break ──────────────────────────────────────────────────────────────
  function stepBreak(): void {
    const s = step(2, 'Break it')
    s.append(el('p', {}, 'Change one bit of the pulse’s secret value — the kind of edit someone rewriting history would make — and run the same five checks.'))
    const out = el('div', { 'aria-live': 'polite' })
    const flip = button('Tamper with it: flip one bit', async () => {
      flip.disabled = true
      const forged = withField(PULSE, 'localRandomValue', flipFirstByte(PULSE.localRandomValue))
      const rows = await runChecks(forged)
      const failed = rows.filter((r) => !r.ok).length
      out.append(
        checkList(rows),
        verdictEl('g-tamper', 'fail', 'TAMPERING DETECTED', `${failed} of ${rows.length} checks fail. The ones that still pass never covered this value.`),
        el('p', { class: 'callout' }, 'Cryptography is excellent at detecting changes. A single bit is enough.'),
        button('Restore the original pulse', () => {
          for (const b of out.querySelectorAll('button')) b.disabled = true
          void stepPunchline()
        }),
      )
    })
    s.append(flip, out)
    flow.appendChild(s)
  }

  // ── 3. Punchline ──────────────────────────────────────────────────────────
  async function stepPunchline(): Promise<void> {
    const s = step(3, 'Everything passes')
    const rows = await runChecks(PULSE)
    const all = rows.every((r) => r.ok)
    s.append(
      el('p', {}, 'The original pulse, untouched, through the same five checks:'),
      checkList(rows),
      el(
        'p',
        { class: 'gscenario' },
        'Now suppose you run a public lottery worth $10 million, and the winner is drawn from this pulse. The beacon operator must not be able to influence it.',
      ),
      choice('Does signature verification alone settle that?', [
        ['Yes', 'Let’s look at when NIST had this value.'],
        ['No', 'Right — let’s see exactly why.'],
      ], () => reveal()),
    )
    flow.appendChild(s)

    function reveal(): void {
      const climax = el(
        'div',
        { class: 'climax', 'data-fixture': 'guided-operator-knows' },
        verdictEl('g-climax', all ? 'warn' : 'fail', all ? 'VERIFIED' : 'NOT VERIFIED'),
        el('p', { class: 'climax-arrow', 'aria-hidden': 'true', text: '↓' }),
        el('p', { class: 'climax-line', 'data-claim': 'g-knew', text: 'But NIST already knew the secret value.' }),
        el(
          'ol',
          { class: 'timeline gtimeline' },
          el(
            'li',
            {},
            el('strong', { text: `${PREV.timeStamp.slice(11, 16)} UTC` }),
            ` NIST holds the value X = ${abbrev(PULSE.localRandomValue, 8, 4)} and publishes only SHA-512(X) = ${abbrev(PREV.precommitmentValue, 8, 4)}, inside pulse #${PREV.pulseIndex}.`,
          ),
          el('li', { class: 'gtimeline-gap', text: '↓ one pulse later' }),
          el(
            'li',
            {},
            el('strong', { text: `${PULSE.timeStamp.slice(11, 16)} UTC` }),
            ` NIST publishes X in pulse #${PULSE.pulseIndex}. Everyone else learns it now.`,
          ),
        ),
        el('p', { class: 'climax-lesson', 'data-claim': 'g-lesson', text: 'Nothing failed. That is the lesson.' }),
        el(
          'p',
          {},
          'Verification answered a different question. It proved the record was not altered and that NIST’s key signed it. It did not prove the signer lacked advance knowledge — and no check could have raised that, because nothing was wrong with the bytes.',
        ),
        button('What if no single operator holds the key?', () => {
          ;(climax.querySelector('button') as HTMLButtonElement).disabled = true
          stepThreshold()
        }),
      )
      s.appendChild(climax)
    }
  }

  // ── 4. Threshold contrast ─────────────────────────────────────────────────
  function stepThreshold(): void {
    const s = step(4, 'No single operator')
    const dealing = deal(T, NAMES.length)
    const partials = dealing.shares.map((sh) => partialSign(sh, ROUND))
    const chosen = new Set<number>()
    const results: Array<{ who: string; sig: string; ok: boolean }> = []
    s.append(
      el('p', {}, `Five operators each hold one share of a signing key. Any ${T} of them can sign round ${ROUND}; no one holds the whole key. Pick who shows up.`),
    )
    const circles = el('div', { class: 'gcircles', role: 'group', 'aria-label': 'Operators who sign' })
    const need = el('p', { class: 'gneed', role: 'status' })
    const out = el('div', { 'aria-live': 'polite' })
    const updateNeed = (): void => {
      need.textContent = `${chosen.size} selected · need ${T}`
    }
    NAMES.forEach((name, i) => {
      const b = el('button', { type: 'button', class: 'gcircle', 'aria-pressed': 'false', 'aria-label': `Operator ${name}`, text: name })
      b.addEventListener('click', () => {
        if (chosen.has(i + 1)) chosen.delete(i + 1)
        else chosen.add(i + 1)
        b.setAttribute('aria-pressed', String(chosen.has(i + 1)))
        updateNeed()
      })
      circles.appendChild(b)
    })
    updateNeed()
    const sign = button('Sign with these operators', () => {
      clear(out)
      if (chosen.size === 0) {
        out.append(verdictEl('g-group', 'fail', 'NO OPERATORS', 'pick at least one.'))
        return
      }
      const c = combine(new Map([...chosen].map((i) => [i, partials[i - 1] as string])))
      const ok = verifyGroup(dealing.groupPublicKey, ROUND, c.signature).ok
      const who = c.signers.map((i) => NAMES[i - 1]).join('+')
      results.push({ who, sig: c.signature, ok })
      const valid = results.filter((r) => r.ok)
      const distinct = new Set(valid.map((r) => r.sig)).size
      const quorums = new Set(valid.map((r) => r.who)).size
      out.append(
        ok
          ? verdictEl('g-group', 'pass', `${who} → SIGNATURE ${c.signature.slice(0, 8)}…`, 'the group key accepts it.')
          : verdictEl('g-group', 'fail', `${who}: ${chosen.size} OF ${T}`, 'no valid group signature.', 'PAIRING_MISMATCH'),
        ...(valid.length === 0
          ? []
          : [el(
          'ul',
          { class: 'gsigs', role: 'list', 'data-claim': 'g-sigs' },
          ...valid.map((r) => el('li', { role: 'listitem', class: 'mono', 'data-sig': r.sig }, `${r.who.padEnd(5)} → ${abbrev(r.sig, 16, 8)}`)),
        )]),
        quorums >= 2 && distinct === 1
          ? el('p', { class: 'same-output', 'data-claim': 'g-same', text: `SAME OUTPUT — ${quorums} different quorums, one signature.` })
          : el('p', { class: 'muted', text: valid.length ? 'Now try a different group of three.' : `Try any ${T}.` }),
        expert(
          'Want to see what actually happened?',
          el('p', {}, 'Each operator signed with its share: σᵢ = skᵢ · H(m). The chosen signatures were combined with Lagrange coefficients:'),
          el(
            'ul',
            { class: 'mono glagrange' },
            ...c.signers.map((i, k) =>
              el('li', {}, `σ${'₁₂₃₄₅'[i - 1]} = ${abbrev(partials[i - 1] as string, 10, 6)}  ${verifyPartial(dealing.sharePublicKeys[i - 1] as string, ROUND, partials[i - 1] as string) ? '(valid share)' : '(invalid share)'}  λ${'₁₂₃₄₅'[i - 1]} = ${abbrev(scalarHex(c.lambdas[k] as bigint), 8, 6)}`),
            ),
          ),
          el('p', { class: 'mono' }, `σ = Σ λᵢ·σᵢ = ${abbrev(c.signature, 16, 8)}`),
          el('p', { class: 'mono' }, `e(σ, g₂) = e(H(m), PK) → ${ok ? '✓ equal' : '✗ different'}`),
          el('p', {}, `With ${T} or more shares the interpolation lands on the one secret every quorum shares, so the signature — and the randomness SHA-256(σ) — cannot depend on who showed up. Fewer than ${T} lands somewhere else. Act 6 does this with the full working.`),
        ),
      )
      if (quorums >= 2 && distinct === 1 && !s.querySelector('.gfinal')) finale()
    })
    s.append(circles, need, sign, out)
    flow.appendChild(s)

    function finale(): void {
      s.appendChild(
        el(
          'div',
          { class: 'gfinal' },
          el('h3', { text: 'Four sentences to keep' }),
          el(
            'ol',
            {},
            el('li', {}, 'A signature can prove who published a value.'),
            el('li', {}, 'A hash chain can prove the history wasn’t rewritten.'),
            el('li', {}, 'Neither proves that the publisher didn’t know the value first.'),
            el('li', {}, 'Threshold cryptography changes who must be trusted. It does not remove trust: enough colluding operators could still sign early.'),
          ),
          el('p', {}, el('a', { href: '#properties', text: 'See both beacons compared property by property' }), ', or ', el('a', { href: '#act1', text: 'start the six acts' }), ' for every byte.'),
        ),
      )
    }
  }
}
