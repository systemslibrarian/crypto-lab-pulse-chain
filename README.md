# Pulse Chain

**NIST Beacon 2.0 · NISTIR 8213 · drand threshold BLS**

Recompute real NIST Randomness Beacon pulses byte by byte, walk their SHA-512 hash chain and skiplist, verify real drand League of Entropy rounds with a BLS12-381 pairing, and find the one thing no check can tell you: whether the operator knew the number first.

> Not production crypto — a teaching demo. To consume a beacon, use the operator's maintained client and pin its keys.

## What It Is

A randomness beacon publishes a fresh random value on a schedule for anyone to use: audit sampling, lotteries, committee selection. This lab verifies two that are in service, using their own published outputs, pinned in the repository:

- **NIST Randomness Beacon 2.0** (chain 2, one pulse per minute), specified by NISTIR 8213 (Draft, May 2019). Each pulse's `outputValue` is SHA-512 over a byte serialization of nineteen fields plus an RSA PKCS #1 v1.5 / SHA-512 signature. Pulses link to the previous pulse and to the first pulse of the hour, day, month and year, and each pulse publishes `precommitmentValue = SHA-512(next localRandomValue)`.
- **drand** (League of Entropy): the `default` chain (`pedersen-bls-chained`: public key on G1, signatures on G2, message `SHA-256(previous_signature ‖ uint64_be(round))`) and `quicknet` (`bls-unchained-g1-rfc9380`: signatures on G1, message `SHA-256(uint64_be(round))`). Randomness is `SHA-256(signature)`. The group key is threshold-shared, so no single member can sign a round.

**Security model.** A beacon is judged on four properties: unpredictability, uniqueness (bias resistance), public verifiability and liveness. Verification can establish integrity (nothing changed after publication) and origin (the key holder signed it). It cannot establish how the key holder chose the value. For NIST that matters directly: the engine holds each `localRandomValue` a full pulse before revealing it.

**What this lab measured, rather than assumed.** It tested every serialization variant against 56 real pulses:

| Question | NISTIR 8213 draft text | What `beacon.nist.gov` computes |
|---|---|---|
| Length prefix of strings and hashes | 8-byte `uint64` (eq. 4) | **4 bytes** |
| `external.statusCode` | `uint64` (Algorithm 2, line 11) | **4 bytes** |
| `outputValue` preimage | signature serialized with its length | **raw 512-byte signature, no prefix** |
| `certificateId` | hash of the PEM file (§4.8.2) | **SHA-512 of the certificate's DER bytes** |

The draft-text reading reproduces **none** of the 56 pulses. `src/nist/nist.test.ts` pins each row as a regression test.

**A dated finding (captured 2026-10-01).** NIST rotated its signing certificate at pulse 1925734 (2026-09-03 21:08 UTC). That pulse self-reports `statusCode 6` (a gap plus a certificate change) after 10 missing pulses. Every pulse since then carries a 4096-bit signature, while the certificate its `certificateId` names (`CN=engine.beacon.nist.gov`, valid 2026-09-03 to 2027-03-20) has a 2048-bit key. Those signatures cannot be verified against the certificate they name, though every hash, link and precommitment still checks. Pulse 1925733, the last under the previous 4096-bit certificate, verifies completely. `scripts/live-check.mjs` re-asks the live service weekly and fails if this changes.

**Real vs simulated.** Every pulse, certificate and round is real and unmodified, and every check is real cryptography: SHA-512 and SHA-256 from `@noble/hashes`; RSA through WebCrypto plus a hand-rolled `s^e mod n` recovery so the padding can be shown; BLS12-381 hash-to-curve and pairings from `@noble/curves`. Act 6's threshold beacon is real BLS arithmetic with simulated signers and a **trusted dealer**. drand itself uses distributed key generation.

**What it does not prove.** It does not show that NIST did not know or choose a value, or that fewer than the threshold of drand members colluded. It does not validate the certificate's own signature or its chain to a CA, NIST's hardware or entropy sources, drand's key ceremony, or the `external.value` field, which is all zeros in every pinned pulse.

## Exhibits

1. **Recompute a NIST pulse.** A byte map of the nineteen serialized fields with offsets and length prefixes, and the published vs recomputed `outputValue` compared digit by digit. Break it two ways: switch to the draft's 8-byte prefixes, or flip one bit of `localRandomValue`.
2. **Walk the chain, then rewrite history.** Eight consecutive signed pulses with four independent checks per row (self-hash, previous link, precommitment, RSA signature). Rewrite one pulse the way a forger without NIST's key would: change it and re-hash it. Three different checks catch it.
3. **Skip from a month ago to now.** A 33-pulse skiplist (NISTIR 8213 Algorithm 6) from pulse 1925733 to 1965616, spanning 39,884 pulses, mostly by `day` links. Remove any pulse and the path breaks at exactly that hop.
4. **Who vouches for the pulse?** Certificate ID, RSA signature (opened by hand to its `00 01 FF…FF 00 ‖ DigestInfo ‖ H` block), precommitment. Pulse 1925733 passes everything and is the negative-claim exhibit: **VERIFIED — AND KNOWN TO THE OPERATOR FIRST**. Post-rotation pulses show the signature/key size mismatch.
5. **Verify a drand round.** The message bytes, hash-to-curve with the right DST, both sides of the pairing equation compared, randomness against the value drand's v1 API published, and chain continuity back to the genesis seed. Break it by claiming the next round or substituting a wrong previous signature.
6. **Why a threshold makes the output unique.** A 3-of-5 BLS beacon. Choose which signers respond, combine partials by Lagrange interpolation in the exponent, and see every quorum produce the same signature while two signers produce nothing valid.
7. **The four properties, side by side.** NIST vs drand. Cells that depend on a check are computed from that check, not written as prose.

## When to Use It

- To learn what a public randomness beacon's outputs can and cannot prove, before relying on one.
- To check your own NIST Beacon 2.0 verifier against real pulses: 4-byte prefixes, 4-byte `external.statusCode`, raw signature in the output hash, DER for `certificateId`.
- To compare a single-operator beacon with a threshold beacon property by property.
- **Do NOT** use this code to consume a beacon in production. It has no network client, no key pinning or rotation handling, and no certificate-chain validation.
- **Do NOT** treat a verified NIST pulse as unpredictable to NIST, or as fit for any use where the operator is an adversary (Act 4).

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-pulse-chain/**

Recompute and tamper with real pulses, verify and break drand rounds, operate a toy threshold beacon, and compare the two beacons on four properties. The page makes no network requests; all data is pinned.

## What Can Go Wrong

- **Trusting the spec text over the deployment.** A verifier written from NISTIR 8213's prose (8-byte lengths, `uint64` external status, PEM-hashed `certificateId`) rejects every real pulse. This lab only found the deployed layout by testing variants against published values.
- **Hash chain mistaken for authenticity.** Anyone can extend or re-hash a chain. Only the signature binds a pulse to NIST, and since the 2026-09-03 rotation it cannot be checked against the certificate the pulses name.
- **Skiplist without self-hashes.** Algorithm 6 checks only the links between entries. A path whose pulses do not each hash to their own `outputValue` proves nothing, so the lab checks both.
- **Operator foreknowledge.** NIST's engine holds each value before release. The precommitment stops it changing its mind after committing; it does not stop it choosing what to commit, or skipping a pulse.
- **Mixing drand schemes.** Using the wrong DST, group, or chained/unchained message format makes valid rounds fail, or makes a verifier accept a round under the wrong chain. Act 5 and the unit tests exercise each.
- **v2 drand responses omit `randomness`.** Deriving it as `SHA-256(signature)` is correct, but there is then nothing published to compare against. This lab keeps the v1 value for that comparison.
- **Threshold collusion.** If at least t drand members collude they can compute rounds early; uniqueness still holds, unpredictability does not.

## Real-World Usage

- **NIST Randomness Beacon** (`beacon.nist.gov`), Version 2.0 Beta, described in NISTIR 8213 (Draft); used for public demonstrations of verifiable randomness and as one input in combined-beacon designs.
- **drand / League of Entropy** (`api.drand.sh`): `default` since 2020, `quicknet` since 2023. Used for timelock encryption (tlock), leader election, and on-chain randomness.

## How to Run Locally

```sh
npm ci
npm run dev          # http://localhost:5173/crypto-lab-pulse-chain/
npm test             # Vitest: unit tests and KATs
npm run build        # both typechecks, then vite build
npx playwright install chromium   # never --with-deps
npm run test:a11y    # every Playwright spec: WCAG gate + claims suite
npm run mutate       # mutation runner (slow; ~10 min)
node scripts/live-check.mjs       # ask the live beacons whether the pinned facts still hold
```

The Playwright preview runs on port **4677**. If your machine's pre-installed Chromium differs from the pinned Playwright build, set `PW_CHROMIUM=/path/to/chrome`; CI never sets it.

## Related Demos

- [crypto-lab-beacon-lock](https://systemslibrarian.github.io/crypto-lab-beacon-lock/): timelock encryption to a future drand quicknet round.
- [crypto-lab-icy-dvrf](https://systemslibrarian.github.io/crypto-lab-icy-dvrf/): the same four-property split for a distributed VRF.
- [crypto-lab-dkg-gate](https://systemslibrarian.github.io/crypto-lab-dkg-gate/): distributed key generation, which replaces Act 6's trusted dealer.
- [crypto-lab-vrf-gate](https://systemslibrarian.github.io/crypto-lab-vrf-gate/): verifiable random functions.

## Build & Verify

| Suite | Count | What it checks |
|---|---|---|
| Vitest (`npm test`) | **52 tests** | 56 real NIST pulses under both layouts, 2 certificates, RSA verify and recovery, hash chain, precommitment, skiplist; 13 real drand rounds by pairing and randomness; threshold toy; byte and DER helpers |
| Spec KATs | 7 vectors | RFC 9380 Appendix J.9.1 hash-to-G1 (5), FIPS 180-4 SHA-512 and SHA-256 "abc" (2), in `src/fixtures/kat.json` |
| Claims suite (`e2e/claims.spec.ts`) | **24 tests** | Headline values re-derived in Node by an independent route; every failure code reached through its control; retirement and a no-op guard; the §4.1d negative claim |
| a11y gate (`e2e/a11y.spec.ts`) | 2 tests (1280px and 380px), 24 scanned states each | axe WCAG 2.1 A/AA (violations and incomplete), arithmetic text contrast, non-text contrast (empty baseline), reflow at 380px, keyboard-reachable scrollers, no invisible focus targets |
| Mutation runner (`npm run mutate`) | **13 mutations, 13 killed** | Concrete patches with owning tests; a kill requires the owner to pass unmutated in the same run, the patch to apply, the bundle hash to move, and the mutant to build |

Fixtures: `src/fixtures/nist.json` (captured from `beacon.nist.gov` on 2026-10-01), `src/fixtures/drand.json` (captured from `api.drand.sh` on 2026-10-01, with each round's v1 `randomness`), `src/fixtures/kat.json`. Nothing in them is computed by the lab.

The e2e directory has its own `tsconfig.e2e.json`. The gate files are copied from `crypto-lab-schnorr-forge`, which is written without `noUncheckedIndexedAccess`, and the lab's own source keeps that stricter setting. `npm run build` typechecks both.

CI (`.github/workflows/`): `deploy.yml` runs unit tests, build, then every Playwright spec before deploying, and gates and auto-merges grouped Dependabot bumps. `mutation.yml` runs the mutation runner on changes to `src/`, `e2e/` or the runner itself. `live-check.yml` runs the drift check weekly.

## Performance

A BLS12-381 pairing in pure JavaScript takes tens of milliseconds, and Act 5 computes two per verification. Act 6 deals five G2 key shares and verifies each partial on demand. RSA verification goes through WebCrypto and is asynchronous, so Acts 2 and 4 render when their verifications resolve. The page marks `#exhibits[data-ready]` once all of them have.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
