/**
 * Claims suite (template §4.1b, §4.1d): does the page tell the truth?
 *
 * Three kinds of assertion, deliberately mixed:
 *
 *  - INDEPENDENT RE-DERIVATIONS. Each headline value is recomputed here, in
 *    Node, by a different route than src/ takes: a separate serializer written
 *    with Buffer writes and node:crypto, a separate BLS verification, the raw
 *    fixture JSON read from disk. A mutation that corrupts the maths in src/
 *    is then caught even when the page reports the corrupted value
 *    consistently everywhere.
 *  - CROSS-CHECKS. Two surfaces the page prints that must agree: a stat vs
 *    the rows it counts, a "distinct values" sentence vs the table it
 *    summarises.
 *  - FAILURE PATHS, RETIREMENT AND NO-OP GUARDS. Every failure the page can
 *    show is reached through its control and must name its own cause; a
 *    changed input must retire a stale verdict and say so; re-selecting the
 *    same input must not.
 *
 * And the negative claim (§4.1d): pulse #1925733 passes every check the page
 * performs, and the page says — in that state, visibly — what those checks do
 * not establish.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js'
import { expect, test, type Page } from '@playwright/test'
import { createHash, verify as nodeVerify, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'

const NIST = JSON.parse(readFileSync(new URL('../src/fixtures/nist.json', import.meta.url), 'utf8'))
const DRAND = JSON.parse(readFileSync(new URL('../src/fixtures/drand.json', import.meta.url), 'utf8'))

/**
 * An independent NIST serializer: Buffer writes and node:crypto, sharing no
 * code with src/nist/serialize.ts. 4-byte length prefixes, 4-byte
 * external.statusCode, raw signature appended for the output value.
 */
function nistOutput(p: any): string {
  const parts: Buffer[] = []
  const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); parts.push(b) }
  const u64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); parts.push(b) }
  const bytes = (b: Buffer) => { u32(b.length); parts.push(b) }
  const str = (s: string) => bytes(Buffer.from(s, 'utf8'))
  const hex = (h: string) => bytes(Buffer.from(h, 'hex'))
  const lv = (t: string) => p.listValues.find((l: any) => l.type === t).value
  str(p.uri); str(p.version); u32(p.cipherSuite); u32(p.period); hex(p.certificateId)
  u64(p.chainIndex); u64(p.pulseIndex); str(p.timeStamp); hex(p.localRandomValue)
  hex(p.external.sourceId); u32(p.external.statusCode); hex(p.external.value)
  for (const t of ['previous', 'hour', 'day', 'month', 'year']) hex(lv(t))
  hex(p.precommitmentValue); u32(p.statusCode)
  const signed = Buffer.concat(parts)
  return createHash('sha512').update(Buffer.concat([signed, Buffer.from(p.signatureValue, 'hex')])).digest('hex').toUpperCase()
}

function signedBytes(p: any): Buffer {
  // Same field walk as nistOutput, without the signature.
  const parts: Buffer[] = []
  const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); parts.push(b) }
  const u64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); parts.push(b) }
  const bytes = (b: Buffer) => { u32(b.length); parts.push(b) }
  const lv = (t: string) => p.listValues.find((l: any) => l.type === t).value
  bytes(Buffer.from(p.uri)); bytes(Buffer.from(p.version)); u32(p.cipherSuite); u32(p.period)
  bytes(Buffer.from(p.certificateId, 'hex')); u64(p.chainIndex); u64(p.pulseIndex)
  bytes(Buffer.from(p.timeStamp)); bytes(Buffer.from(p.localRandomValue, 'hex'))
  bytes(Buffer.from(p.external.sourceId, 'hex')); u32(p.external.statusCode); bytes(Buffer.from(p.external.value, 'hex'))
  for (const t of ['previous', 'hour', 'day', 'month', 'year']) bytes(Buffer.from(lv(t), 'hex'))
  bytes(Buffer.from(p.precommitmentValue, 'hex')); u32(p.statusCode)
  return Buffer.concat(parts)
}

async function open(page: Page): Promise<void> {
  await page.goto('.')
  await expect(page.locator('#exhibits')).toHaveAttribute('data-ready', 'true')
}

const verdictOf = (page: Page, check: string) => page.locator(`[data-check="${check}"]`)

test.beforeEach(async ({ page }) => {
  page.setDefaultTimeout(20_000)
  await open(page)
})

test.describe('Act 1 — the recomputed outputValue', () => {
  test('both printed values equal an independent SHA-512 of the newest pulse', async ({ page }) => {
    const p = NIST.recent.at(-1)
    const published = await page.locator('[data-claim="a1-published"]').textContent()
    const computed = await page.locator('[data-claim="a1-computed"]').textContent()
    const independent = nistOutput(p)
    expect(independent).toBe(p.outputValue)
    expect(published).toBe(p.outputValue)
    expect(computed).toBe(independent)
    await expect(verdictOf(page, 'a1-output')).toHaveAttribute('data-verdict', 'pass')
  })

  test('the byte map’s offsets sum to the signed length an independent serializer produces', async ({ page }) => {
    const p = NIST.recent.at(-1)
    const offsets = await page.locator('[data-claim="bytemap"] td[data-offset]').evaluateAll((els) =>
      els.map((e) => Number(e.getAttribute('data-offset'))),
    )
    expect(offsets).toHaveLength(19)
    const prefixes = await page.locator('[data-claim="bytemap"] td[data-prefix]').evaluateAll((els) =>
      els.map((e) => e.getAttribute('data-prefix') ?? ''),
    )
    // Offsets strictly increase; the last field (statusCode, 4 bytes) ends where the signed bytes end.
    for (let i = 1; i < offsets.length; i++) expect(offsets[i]).toBeGreaterThan(offsets[i - 1]!)
    expect(offsets.at(-1)! + 4).toBe(signedBytes(p).length)
    // Every non-empty prefix is 4 bytes wide in the deployed layout.
    for (const pr of prefixes.filter((x) => x.length)) expect(pr).toHaveLength(8)
  })

  test('the 8-byte draft layout fails with OUTPUT_MISMATCH and widens every prefix', async ({ page }) => {
    await page.locator('label[for="a1-layout-draft"]').click()
    await expect(verdictOf(page, 'a1-output')).toHaveAttribute('data-code', 'OUTPUT_MISMATCH')
    await expect(verdictOf(page, 'a1-output')).toContainText('8-byte length prefixes')
    const prefixes = await page.locator('[data-claim="bytemap"] td[data-prefix]').evaluateAll((els) =>
      els.map((e) => e.getAttribute('data-prefix') ?? '').filter((x) => x.length),
    )
    for (const pr of prefixes) expect(pr).toHaveLength(16)
    // The published value is unchanged; only the recomputation moved.
    expect(await page.locator('[data-claim="a1-published"]').textContent()).toBe(NIST.recent.at(-1).outputValue)
  })

  test('one flipped bit is named as the cause, and flipping back restores the match', async ({ page }) => {
    const btn = page.locator('#act1').getByRole('button', { name: 'Flip one bit of localRandomValue' })
    await btn.click()
    await expect(verdictOf(page, 'a1-output')).toHaveAttribute('data-verdict', 'fail')
    await expect(verdictOf(page, 'a1-output')).toContainText('One flipped bit')
    const p = structuredClone(NIST.recent.at(-1))
    const b = Buffer.from(p.localRandomValue, 'hex'); b[0] ^= 1; p.localRandomValue = b.toString('hex').toUpperCase()
    expect(await page.locator('[data-claim="a1-computed"]').textContent()).toBe(nistOutput(p))
    await btn.click()
    await expect(verdictOf(page, 'a1-output')).toHaveAttribute('data-verdict', 'pass')
  })
})

test.describe('Act 2 — rewriting history', () => {
  test('arrival: every row passes, independently re-derived', async ({ page }) => {
    await expect(verdictOf(page, 'a2-chain')).toHaveAttribute('data-verdict', 'pass')
    const run = NIST.preRotation
    for (let i = 1; i < run.length; i++) {
      expect(run[i].listValues.find((l: any) => l.type === 'previous').value).toBe(run[i - 1].outputValue)
      expect(createHash('sha512').update(Buffer.from(run[i].localRandomValue, 'hex')).digest('hex').toUpperCase()).toBe(run[i - 1].precommitmentValue)
    }
    await expect(page.locator('#act2 [data-check="a2-sig"][data-verdict="pass"]')).toHaveCount(run.length)
  })

  test('a rewrite is caught by exactly the three checks the page names', async ({ page }) => {
    const target = NIST.preRotation[3].pulseIndex
    await page.locator('#a2-target').selectOption(String(target))
    await page.getByRole('button', { name: 'Rewrite it (forger re-hashes)' }).click()
    await expect(verdictOf(page, 'a2-chain')).toContainText('REWRITE DETECTED')
    await expect(verdictOf(page, 'a2-chain')).toContainText('3 independent checks')
    const row = page.locator(`#act2 tr[data-pulse="${target}"]`)
    await expect(row.locator('[data-check="a2-own"]')).toHaveAttribute('data-verdict', 'pass')
    await expect(row.locator('[data-check="a2-sig"]')).toHaveAttribute('data-code', 'SIG_INVALID')
    await expect(row.locator('[data-check="a2-precommit"]')).toHaveAttribute('data-code', 'PRECOMMIT_MISMATCH')
    const next = page.locator(`#act2 tr[data-pulse="${target + 1}"]`)
    await expect(next.locator('[data-check="a2-link"]')).toHaveAttribute('data-code', 'LINK_BROKEN')
    // Independently: the forged pulse's signed bytes no longer verify under NIST's real key.
    const p = structuredClone(NIST.preRotation[3])
    const b = Buffer.from(p.localRandomValue, 'hex'); b[0] ^= 1; p.localRandomValue = b.toString('hex')
    const cert = new X509Certificate(NIST.certificates[p.certificateId])
    expect(nodeVerify('sha512', signedBytes(p), cert.publicKey, Buffer.from(p.signatureValue, 'hex'))).toBe(false)
    expect(nodeVerify('sha512', signedBytes(NIST.preRotation[3]), cert.publicKey, Buffer.from(p.signatureValue, 'hex'))).toBe(true)
    // Every other row is untouched.
    await expect(page.locator('#act2 [data-verdict="fail"]')).toHaveCount(4)
  })

  test('retirement: a different target undoes the rewrite and says so', async ({ page }) => {
    await page.getByRole('button', { name: 'Rewrite it (forger re-hashes)' }).click()
    await expect(verdictOf(page, 'a2-chain')).toContainText('REWRITE DETECTED')
    await page.locator('#a2-target').selectOption(String(NIST.preRotation[2].pulseIndex))
    await expect(verdictOf(page, 'a2-chain')).toContainText('INTACT')
    await expect(page.locator('[data-claim="a2-status"]')).toContainText('previous rewrite was undone')
  })

  test('no-op guard: re-selecting the same target keeps the rewrite', async ({ page }) => {
    const same = await page.locator('#a2-target').inputValue()
    await page.getByRole('button', { name: 'Rewrite it (forger re-hashes)' }).click()
    await expect(verdictOf(page, 'a2-chain')).toContainText('REWRITE DETECTED')
    await page.locator('#a2-target').selectOption(same)
    await expect(verdictOf(page, 'a2-chain')).toContainText('REWRITE DETECTED')
    await expect(page.locator('[data-claim="a2-status"]')).not.toContainText('undone')
  })
})

test.describe('Act 3 — skiplist', () => {
  test('the stat equals the rows, and every hop is independently carried by a link', async ({ page }) => {
    const rows = page.locator('#act3 tbody tr')
    const n = await rows.count()
    await expect(page.locator('#act3 .stat', { hasText: 'Pulses this path checks' })).toContainText(String(n))
    const path = NIST.skiplist.pulses
    expect(n).toBe(path.length)
    for (let i = 1; i < path.length; i++) {
      const vals = path[i].listValues.map((l: any) => l.value)
      expect(vals).toContain(path[i - 1].outputValue)
    }
    await expect(page.locator('#act3 .stat', { hasText: 'between target and anchor' })).toContainText(
      (NIST.skiplist.anchor - NIST.skiplist.target + 1).toLocaleString('en-US'),
    )
    await expect(verdictOf(page, 'a3-skiplist')).toHaveAttribute('data-verdict', 'pass')
  })

  test('dropping a pulse breaks the path at the hop it names', async ({ page }) => {
    const path = NIST.skiplist.pulses
    await page.locator('#a3-drop').selectOption('10')
    await expect(verdictOf(page, 'a3-skiplist')).toHaveAttribute('data-code', 'SKIPLIST_BROKEN')
    await expect(verdictOf(page, 'a3-skiplist')).toContainText(`from #${path[9].pulseIndex} to #${path[11].pulseIndex}`)
    expect(path[11].listValues.map((l: any) => l.value)).not.toContain(path[9].outputValue)
    await page.locator('#a3-drop').selectOption('')
    await expect(verdictOf(page, 'a3-skiplist')).toHaveAttribute('data-verdict', 'pass')
  })
})

test.describe('Act 4 — the negative claim (§4.1d)', () => {
  test('pulse #1925733: every check passes, and the page says what that does not show', async ({ page }) => {
    // 1. Reach the fixture (it is the default).
    await expect(page.locator('#a4-pulse-signed')).toBeChecked()
    const fixture = page.locator('[data-fixture="operator-knows"]')
    await expect(fixture).toBeVisible()
    // 2. Everything is green — every check the page renders in this state.
    for (const c of ['a4-output', 'a4-certid', 'a4-sig', 'a4-precommit']) {
      await expect(verdictOf(page, c)).toHaveAttribute('data-verdict', 'pass')
    }
    await expect(page.locator('#act4 [data-verdict="fail"]')).toHaveCount(0)
    // Independently: NIST's signature on this pulse verifies under the pinned certificate.
    const p = NIST.preRotation.at(-1)
    const cert = new X509Certificate(NIST.certificates[p.certificateId])
    expect(createHash('sha512').update(cert.raw).digest('hex')).toBe(p.certificateId)
    expect(nodeVerify('sha512', signedBytes(p), cert.publicKey, Buffer.from(p.signatureValue, 'hex'))).toBe(true)
    // 3. The limitation is on screen, in this state, inside the fixture.
    await expect(verdictOf(page, 'a4-headline')).toHaveText(/VERIFIED — AND KNOWN TO THE OPERATOR FIRST/)
    await expect(verdictOf(page, 'a4-headline')).toHaveAttribute('data-verdict', 'warn')
    const claim = fixture.locator('[data-claim="negative-claim"]')
    await expect(claim).toBeVisible()
    await expect(claim).toContainText('does not show this value was unpredictable to NIST')
    // The timeline's commitment is real: SHA-512(localRandomValue) is the previous pulse's precommitmentValue.
    const prev = NIST.preRotation.at(-2)
    expect(createHash('sha512').update(Buffer.from(p.localRandomValue, 'hex')).digest('hex').toUpperCase()).toBe(prev.precommitmentValue)
    await expect(fixture).toContainText(`pulse #${prev.pulseIndex}`)
  })

  test('the newest pulse: hashes pass, origin fails with SIG_SIZE_MISMATCH, and no negative-claim fixture', async ({ page }) => {
    await page.locator('label[for="a4-pulse-latest"]').click()
    await expect(verdictOf(page, 'a4-headline')).toContainText('ORIGIN CANNOT BE CHECKED')
    await expect(verdictOf(page, 'a4-sig')).toHaveAttribute('data-code', 'SIG_SIZE_MISMATCH')
    await expect(verdictOf(page, 'a4-output')).toHaveAttribute('data-verdict', 'pass')
    await expect(verdictOf(page, 'a4-certid')).toHaveAttribute('data-verdict', 'pass')
    await expect(page.locator('[data-fixture="operator-knows"]')).toHaveCount(0)
    // Independently: the signature is 4096 bits and the named certificate's key is 2048.
    const p = NIST.recent.at(-1)
    const cert = new X509Certificate(NIST.certificates[p.certificateId])
    expect(Buffer.from(p.signatureValue, 'hex').length * 8).toBe(4096)
    expect(cert.publicKey.asymmetricKeyDetails?.modulusLength).toBe(2048)
    await expect(verdictOf(page, 'a4-sig')).toContainText('4096-bit signature')
    await expect(verdictOf(page, 'a4-sig')).toContainText('2048-bit key')
  })

  test('the rotation pulse names both status flags', async ({ page }) => {
    await page.locator('label[for="a4-pulse-rotation"]').click()
    await expect(page.locator('#act4 .meta')).toContainText('statusCode 6')
    await expect(page.locator('#act4 .meta')).toContainText('gap')
    await expect(page.locator('#act4 .meta')).toContainText('certificateId changed')
  })
})

test.describe('Act 5 — drand', () => {
  test('VALID ROUND agrees with an independent pairing check, and randomness with SHA-256', async ({ page }) => {
    const r = DRAND.default.recentRounds.at(-1)
    await expect(verdictOf(page, 'a5-pairing')).toContainText(`Round ${r.round.toLocaleString('en-US')}`)
    const pk = bls.G1.Point.fromHex(DRAND.default.info.public_key)
    const msg = createHash('sha256').update(Buffer.concat([Buffer.from(r.previous_signature, 'hex'), (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(r.round)); return b })()])).digest()
    const h = bls.G2.hashToCurve(msg, { DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_' })
    const ok = bls.fields.Fp12.eql(bls.pairing(pk, h), bls.pairing(bls.G1.Point.BASE, bls.G2.Point.fromHex(r.signature)))
    expect(ok).toBe(true)
    await expect(verdictOf(page, 'a5-pairing')).toHaveAttribute('data-verdict', 'pass')
    expect(createHash('sha256').update(Buffer.from(r.signature, 'hex')).digest('hex')).toBe(r.v1Randomness)
    await expect(page.locator('#act5')).toContainText(r.v1Randomness)
    await expect(verdictOf(page, 'a5-randomness')).toHaveAttribute('data-verdict', 'pass')
  })

  test('a wrong round and a wrong previous signature are each rejected with PAIRING_MISMATCH', async ({ page }) => {
    const roundBtn = page.locator('#act5').getByRole('button', { name: 'Claim it is the next round' })
    await roundBtn.click()
    await expect(verdictOf(page, 'a5-pairing')).toHaveAttribute('data-code', 'PAIRING_MISMATCH')
    await expect(page.locator('[data-check="a5-randomness"]')).toHaveCount(0)
    await roundBtn.click()
    await page.locator('#act5').getByRole('button', { name: 'Use the wrong previous signature' }).click()
    await expect(verdictOf(page, 'a5-pairing')).toHaveAttribute('data-code', 'PAIRING_MISMATCH')
  })

  test('round 1 is anchored at the genesis seed the chain info publishes', async ({ page }) => {
    await page.locator('#a5-round').selectOption('1')
    await expect(verdictOf(page, 'a5-continuity')).toContainText('ANCHORED AT GENESIS')
    expect(DRAND.default.genesisRounds[0].previous_signature).toBe(DRAND.default.info.genesis_seed)
  })

  test('quicknet verifies unchained, and the chained-only control is disabled', async ({ page }) => {
    await page.locator('label[for="a5-chain-quicknet"]').click()
    await expect(verdictOf(page, 'a5-pairing')).toHaveAttribute('data-verdict', 'pass')
    await expect(page.locator('#act5').getByRole('button', { name: 'Use the wrong previous signature' })).toBeDisabled()
    await expect(page.locator('[data-check="a5-continuity"]')).toHaveCount(0)
  })
})

test.describe('Act 6 — threshold uniqueness', () => {
  test('the page’s group signature verifies independently under the page’s group key', async ({ page }) => {
    await expect(verdictOf(page, 'a6-group')).toHaveAttribute('data-verdict', 'pass')
    const gpk = await page.locator('[data-claim="a6-gpk"]').getAttribute('data-full')
    const sig = await page.locator('[data-claim="a6-signature"]').textContent()
    const m = createHash('sha256').update((() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(1000n); return b })()).digest()
    const h = bls.G1.hashToCurve(m, { DST: 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_' })
    const ok = bls.fields.Fp12.eql(bls.pairing(bls.G1.Point.fromHex(sig!), bls.G2.Point.BASE), bls.pairing(h, bls.G2.Point.fromHex(gpk!)))
    expect(ok).toBe(true)
  })

  test('two different quorums print the same signature, and the summary counts one distinct value', async ({ page }) => {
    const first = await page.locator('[data-claim="a6-signature"]').textContent()
    for (const s of ['Signer 1', 'Signer 2', 'Signer 4', 'Signer 5']) await page.locator('#act6 .signer', { hasText: s }).click()
    await expect(page.locator('#act6 .signer[aria-pressed="true"]')).toHaveCount(3)
    await page.getByRole('button', { name: 'Combine partial signatures' }).click()
    await expect(verdictOf(page, 'a6-group')).toContainText('signers {3, 4, 5}')
    expect(await page.locator('[data-claim="a6-signature"]').textContent()).toBe(first)
    const sigs = await page.locator('#act6 td[data-sig]').evaluateAll((els) => els.map((e) => e.getAttribute('data-sig')))
    expect(sigs).toHaveLength(2)
    expect(new Set(sigs).size).toBe(1)
    const summary = page.locator('[data-claim="a6-distinct"]')
    await expect(summary).toHaveAttribute('data-distinct', '1')
    await expect(summary).toHaveAttribute('data-valid', '2')
    await expect(summary).toContainText('1 distinct value')
  })

  test('below threshold is rejected and names the threshold', async ({ page }) => {
    await page.locator('#act6 .signer', { hasText: 'Signer 1' }).click()
    await page.getByRole('button', { name: 'Combine partial signatures' }).click()
    await expect(verdictOf(page, 'a6-group')).toHaveAttribute('data-verdict', 'fail')
    await expect(verdictOf(page, 'a6-group')).toContainText('below the threshold of 3')
  })

  test('retirement: changing the signer set clears the old verdict and says so', async ({ page }) => {
    await expect(verdictOf(page, 'a6-group')).toHaveCount(1)
    await page.locator('#act6 .signer', { hasText: 'Signer 4' }).click()
    await expect(verdictOf(page, 'a6-group')).toHaveCount(0)
    await expect(page.locator('[data-claim="a6-status"]')).toContainText('has been cleared')
  })
})

test.describe('The four properties', () => {
  test('the NIST verifiability cell reflects the Act 4 signature result, not prose', async ({ page }) => {
    const cell = page.locator('td[data-property="verifiability"][data-beacon="nist"]')
    await expect(cell).toHaveAttribute('data-level', 'partial')
    await page.locator('label[for="a4-pulse-latest"]').click()
    const sigText = (await verdictOf(page, 'a4-sig').locator('.verdict-detail').textContent())!.trim().replace(/\.$/, '')
    await expect(cell).toContainText(sigText)
  })

  test('the NIST liveness cell’s gap equals the fixture timestamps', async ({ page }) => {
    const gap = (Date.parse(NIST.rotation.timeStamp) - Date.parse(NIST.preRotation.at(-1).timeStamp)) / 60000 - 1
    await expect(page.locator('td[data-property="liveness"][data-beacon="nist"]')).toContainText(`${gap} missing pulses`)
  })
})

test('[hidden] probe: nothing marked hidden is painted', async ({ page }) => {
  const painted = await page.$$eval('[hidden]', (els) => els.filter((e) => (e as HTMLElement).checkVisibility()).length)
  expect(painted).toBe(0)
})
