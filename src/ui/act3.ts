/**
 * Act 3 — Skiplist. Verify a pulse from a month ago against today's, without
 * downloading the 39,883 pulses between them.
 */
import { abbrev } from '../core/bytes'
import { NIST } from '../nist/fixtures'
import type { Pulse } from '../nist/types'
import { checkOutputValue, verifySkiplist } from '../nist/verify'
import { clear, el, expert, labelledSelect, panel, stat, statRow } from './dom'
import { scroller, tag, verdictEl } from './verdict'

const PATH: Pulse[] = NIST.skiplist.pulses

export function mountAct3(host: HTMLElement): void {
  const sec = panel(
    'act3',
    'Act 3 · Skip from a month ago to now',
    'Besides previous, every pulse also carries the outputValue of the first pulse of its hour, day, month and year. Those links let a short path connect any old pulse to a new one.',
  )
  sec.setAttribute('data-act', '3')
  const { wrap, select } = labelledSelect('a3-drop', 'Remove one pulse from the path', [
    { value: '', text: 'Nothing — the path as NIST’s links give it' },
    ...PATH.slice(1, -1).map((p, i) => ({ value: String(i + 1), text: `#${p.pulseIndex} (${p.timeStamp.slice(0, 16).replace('T', ' ')})` })),
  ])
  const out = el('div', { class: 'act-out' })

  function render(): void {
    clear(out)
    const drop = select.value === '' ? -1 : Number(select.value)
    const path = drop < 0 ? PATH : PATH.filter((_, i) => i !== drop)
    const r = verifySkiplist(path)
    const span = NIST.skiplist.anchor - NIST.skiplist.target
    const rows = path.map((p, i) => {
      const hop = i > 0 ? r.hops[i - 1]! : null
      const own = checkOutputValue(p)
      return el(
        'tr',
        { class: hop && hop.via === null ? 'row-tampered' : '' },
        el('th', { scope: 'row', text: `#${p.pulseIndex}` }),
        el('td', { class: 'mono', text: p.timeStamp.slice(0, 16).replace('T', ' ') }),
        el('td', {}, hop ? tag('a3-hop', hop.via !== null, `via ${hop.via ?? ''}`, 'no link', 'SKIPLIST_BROKEN') : el('span', { class: 'muted', text: 'TARGET' })),
        el('td', {}, tag('a3-own', own.ok, 'hashes', 'mismatch', own.code)),
        el('td', { class: 'mono', text: abbrev(p.outputValue, 10, 6) }),
      )
    })
    out.append(
      statRow(
        stat('Pulses between target and anchor', (span + 1).toLocaleString('en-US')),
        stat('Pulses this path checks', String(path.length), 'ok'),
        stat('Hops by day / hour / previous', ['day', 'hour', 'previous'].map((t) => r.hops.filter((h) => h.via === t).length).join(' / ')),
      ),
      scroller(
        'Skiplist path from target to anchor',
        el(
          'table',
          { class: 'chain' },
          el('caption', { text: `From #${NIST.skiplist.target} (TARGET) to #${NIST.skiplist.anchor} (ANCHOR)` }),
          el('thead', {}, el('tr', {}, ...['Pulse', 'Time (UTC)', 'Link to the entry above', 'Self-hash', 'outputValue'].map((h) => el('th', { scope: 'col', text: h })))),
          el('tbody', {}, ...rows),
        ),
      ),
      r.ok
        ? verdictEl('a3-skiplist', 'pass', 'PATH VERIFIES', `Each of the ${r.hops.length} hops is carried by a linking field (Algorithm 6). Trusting the anchor now vouches for the target.`)
        : verdictEl(
            'a3-skiplist',
            'fail',
            'PATH BROKEN',
            `Hop ${r.brokenAt! + 1}, from #${r.hops[r.brokenAt!]!.from} to #${r.hops[r.brokenAt!]!.to}: no linking field of the later pulse carries the earlier pulse’s outputValue.`,
            r.code,
          ),
    )
  }
  select.addEventListener('change', render)
  sec.append(
    el('div', { class: 'controls' }, wrap),
    out,
    expert(
      'How the path was built, and what it does not prove',
      el('p', {}, 'Starting from the anchor, the lab followed whichever of the anchor’s five links (previous, hour, day, month, year) lands nearest the target without passing it, fetching each pulse by the URI the link names. NISTIR 8213 Algorithm 5 builds the same kind of path forward from the target; Table 7 expects about 60 pulses for a month.'),
      el('p', {}, 'Algorithm 6 only checks the links. It does not check that each pulse hashes to its own outputValue, so the lab shows that as a separate column. A path also proves consistency, not authorship: it says the target and the anchor are on one chain, and the anchor’s signature (Act 4) is what says whose chain it is.'),
    ),
  )
  host.appendChild(sec)
  render()
}
