import { el, panel } from './dom'

export function mountScope(host: HTMLElement): void {
  const sec = panel('scope', 'What is real here, and what this does not prove')
  sec.append(
    el(
      'ul',
      { class: 'scope', role: 'list' },
      el('li', { role: 'listitem' }, el('strong', { text: 'Real: ' }), 'every NIST pulse, certificate and drand round on this page was published by the beacon itself and is checked with real cryptography (SHA-512, SHA-256, RSA PKCS #1 v1.5 through WebCrypto, BLS12-381 pairings through @noble/curves).'),
      el('li', { role: 'listitem' }, el('strong', { text: 'Simplified: ' }), 'the threshold demo in Act 6 uses a trusted dealer instead of distributed key generation, and its five signers are simulated in this tab.'),
      el('li', { role: 'listitem' }, el('strong', { text: 'Frozen: ' }), 'the data is a snapshot pinned in the repository. The page does not fetch live pulses, so a later change at NIST or drand will not show here until the fixtures are refreshed.'),
      el('li', { role: 'listitem' }, el('strong', { text: 'Not checked: ' }), 'the certificate’s own signature and its chain to a certificate authority; NIST’s hardware and entropy sources; drand’s key generation ceremony; the external.value field, which is all zeros in every pinned pulse.'),
      el('li', { role: 'listitem' }, el('strong', { text: 'Does not prove: ' }), 'that NIST did not know or choose a pulse’s value (Act 4), or that fewer than the threshold of drand members colluded. Verification shows a value was published by the key holder and not altered since. It cannot show how the key holder chose it.'),
      el('li', { role: 'listitem' }, el('strong', { text: 'Not production crypto: ' }), 'a teaching demo. To consume a beacon, use the operator’s maintained client and pin its keys.'),
    ),
  )
  host.appendChild(sec)
}
