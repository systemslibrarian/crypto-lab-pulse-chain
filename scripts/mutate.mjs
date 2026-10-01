#!/usr/bin/env node
/**
 * Mutation runner (template §4.1c, "a lab that renders verdict markers runs
 * its mutations from a script").
 *
 * Each mutation is a CONCRETE PATCH: a file, an anchor that must occur exactly
 * once, and its replacement — never a sentence describing an edit. A mutation
 * counts as KILLED only when all four hold, and this script checks each one:
 *
 *   1. the owning test PASSED unmutated, in this same run (baseline phase);
 *   2. the patch actually CHANGED the file (anchor found exactly once);
 *   3. the run served the MUTATED code — for e2e owners the built bundle's
 *      hash must differ from the baseline bundle's, and the run is pinned
 *      with CI=1 so `reuseExistingServer` cannot answer with a stale preview;
 *   4. the mutated source BUILDS — a patch that fails `tsc` or `vite build`
 *      is reported DOES NOT BUILD and is never a kill.
 *
 * Every observed record is written by this script to .mutation/observed.json
 * (gitignored) and printed. Nothing is typed by hand. The run exits non-zero
 * unless every mutation is KILLED, so a surviving mutation fails CI-style.
 *
 * Usage: npm run mutate            (all)
 *        npm run mutate -- M3 M5   (by id)
 */
import { execSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'

const MUTATIONS = [
  {
    id: 'M1',
    what: 'deployed layout uses 8-byte length prefixes (the draft-text bug)',
    file: 'src/nist/serialize.ts',
    anchor: "name: 'as deployed (4-byte lengths)',\n  lengthPrefix: 4,",
    replace: "name: 'as deployed (4-byte lengths)',\n  lengthPrefix: 8,",
    owner: { kind: 'e2e', grep: 'both printed values equal an independent SHA-512' },
  },
  {
    id: 'M2',
    what: 'precommitment check always passes',
    file: 'src/nist/verify.ts',
    anchor: 'const ok = opened === committed',
    replace: 'const ok = true',
    owner: { kind: 'e2e', grep: 'a rewrite is caught by exactly the three checks' },
  },
  {
    id: 'M3',
    what: 'skiplist verifier never records a broken hop',
    file: 'src/nist/verify.ts',
    anchor: 'if (via === null && brokenAt === null) brokenAt = hops.length - 1',
    replace: 'if (false) brokenAt = hops.length - 1',
    owner: { kind: 'e2e', grep: 'dropping a pulse breaks the path' },
  },
  {
    id: 'M4',
    what: 'signature/key size mismatch is not detected (falls through to WebCrypto)',
    file: 'src/nist/verify.ts',
    anchor: 'if (sig.length !== Math.ceil(keyBits / 8)) {',
    replace: 'if (false) {',
    owner: { kind: 'e2e', grep: 'origin fails with SIG_SIZE_MISMATCH' },
  },
  {
    id: 'M5',
    what: 'negative-claim text deleted (§4.1d assertion 3 must fail)',
    file: 'src/ui/act4.ts',
    anchor: "'data-claim': 'negative-claim' }, NEGATIVE_CLAIM)",
    replace: "'data-claim': 'negative-claim' }, '')",
    owner: { kind: 'e2e', grep: 'every check passes, and the page says what that does not show' },
  },
  {
    id: 'M6',
    what: 'certificateId hashed over the PEM text, as the draft describes (§4.1d assertion 2 must fail)',
    file: 'src/nist/verify.ts',
    anchor: 'const ok = derHash === p.certificateId.toLowerCase()',
    replace: 'const ok = pemHash === p.certificateId.toLowerCase()',
    owner: { kind: 'e2e', grep: 'every check passes, and the page says what that does not show' },
  },
  {
    id: 'M7',
    what: 'default chain hashes to G2 under the G1 DST',
    file: 'src/drand/verify.ts',
    anchor: "const hm = bls.G2.hashToCurve(m, { DST: DST_G2 })",
    replace: "const hm = bls.G2.hashToCurve(m, { DST: DST_G1 })",
    owner: { kind: 'e2e', grep: 'VALID ROUND agrees with an independent pairing check' },
  },
  {
    id: 'M8',
    what: 'randomness derived from the wrong bytes',
    file: 'src/drand/verify.ts',
    anchor: 'return toHex(sha256(fromHex(signature)))',
    replace: 'return toHex(sha256(fromHex(signature.slice(2))))',
    owner: { kind: 'e2e', grep: 'VALID ROUND agrees with an independent pairing check' },
  },
  {
    id: 'M9',
    what: 'Lagrange numerator off by one',
    file: 'src/threshold/toy.ts',
    anchor: 'num = mod(num * BigInt(j))',
    replace: 'num = mod(num * BigInt(j + 1))',
    owner: { kind: 'e2e', grep: 'group signature verifies independently' },
  },
  {
    id: 'M10',
    what: 'liveness gap counts the minutes, not the missing pulses',
    file: 'src/ui/properties.ts',
    anchor: '/ 60_000 - 1',
    replace: '/ 60_000',
    owner: { kind: 'e2e', grep: 'liveness cell’s gap equals the fixture timestamps' },
  },
  {
    id: 'M11',
    what: 'Act 6 leaves a stale verdict when the signer set changes',
    file: 'src/ui/act6.ts',
    anchor: "const had = out.querySelector('[data-check=\"a6-group\"]') !== null\n        clear(out)",
    replace: "const had = out.querySelector('[data-check=\"a6-group\"]') !== null",
    owner: { kind: 'e2e', grep: 'retirement: changing the signer set' },
  },
  {
    id: 'M12',
    what: 'Act 2 retires the rewrite even when the same target is re-selected',
    file: 'src/ui/act2.ts',
    anchor: 'if (forged !== null && Number(select.value) !== forged) {',
    replace: 'if (forged !== null) {',
    owner: { kind: 'e2e', grep: 'no-op guard: re-selecting the same target' },
  },
  {
    id: 'M13',
    what: 'external.statusCode serialized as uint64 in the deployed layout',
    file: 'src/nist/serialize.ts',
    anchor: '  lengthPrefix: 4,\n  extStatus: 4,',
    replace: '  lengthPrefix: 4,\n  extStatus: 8,',
    owner: { kind: 'vitest', file: 'src/nist/nist.test.ts', name: 'equals the published outputValue' },
  },
  {
    id: 'M14',
    what: 'guided punchline lesson deleted (negative claim must stay on screen)',
    file: 'src/ui/guided.ts',
    anchor: "text: 'Nothing failed. That is the lesson.'",
    replace: "text: ''",
    owner: { kind: 'e2e', grep: 'step 3 (negative claim)' },
  },
  {
    id: 'M15',
    what: 'finding card reports the signature as passing regardless',
    file: 'src/ui/finding.ts',
    anchor: "row('Signature verification', 'f-sig', sig.ok, sig.code)",
    replace: "row('Signature verification', 'f-sig', true, sig.code)",
    owner: { kind: 'e2e', grep: 'every row but the signature passes' },
  },
  {
    id: 'M16',
    what: 'guided tamper step forgets to flip the bit',
    file: 'src/ui/guided.ts',
    anchor: "withField(PULSE, 'localRandomValue', flipFirstByte(PULSE.localRandomValue))",
    replace: "withField(PULSE, 'localRandomValue', PULSE.localRandomValue)",
    owner: { kind: 'e2e', grep: 'step 2: one flipped bit' },
  },
]

const only = process.argv.slice(2)
const selected = only.length ? MUTATIONS.filter((m) => only.includes(m.id)) : MUTATIONS
const env = { ...process.env, CI: '1' }

function sh(cmd) {
  const r = spawnSync(cmd, { shell: true, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  return { ok: r.status === 0, out: (r.stdout ?? '') + (r.stderr ?? '') }
}

function bundleHash() {
  const dir = 'dist/assets'
  const js = readdirSync(dir).filter((f) => f.endsWith('.js')).sort()
  const h = createHash('sha256')
  for (const f of js) h.update(readFileSync(`${dir}/${f}`))
  return h.digest('hex').slice(0, 16)
}

function build() {
  const r = sh('npm run build')
  return r.ok ? { ok: true, hash: bundleHash() } : { ok: false, out: r.out.slice(-2000) }
}

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const INFRA = /was not able to start|is already used|ECONNREFUSED|Executable doesn't exist/

function runOwner(owner) {
  if (owner.kind === 'vitest') {
    const r = sh(`npx vitest run ${owner.file} -t "${owner.name}"`)
    const ran = /Tests\s+\d+ (passed|failed)/.test(r.out) && !/no tests/i.test(r.out)
    return { passed: r.ok, ran, infra: false, out: r.out }
  }
  const r = sh(`npx playwright test e2e/claims.spec.ts --retries=0 -g "${escape(owner.grep)}"`)
  const ran = /\d+ (passed|failed)/.test(r.out)
  return { passed: r.ok, ran, infra: INFRA.test(r.out), out: r.out }
}

mkdirSync('.mutation', { recursive: true })
const observed = { startedAt: new Date().toISOString(), baseline: {}, mutations: [] }

// ── Phase 1: baseline. Every owning test must pass unmutated, in this run. ──
const base = build()
if (!base.ok) {
  console.error('Baseline does not build:\n' + base.out)
  process.exit(2)
}
observed.baseline.bundle = base.hash
console.log(`baseline bundle ${base.hash}`)
const ownersPassed = new Map()
for (const m of selected) {
  const key = JSON.stringify(m.owner)
  if (ownersPassed.has(key)) continue
  const r = runOwner(m.owner)
  ownersPassed.set(key, r.passed && r.ran)
  console.log(`baseline ${r.passed && r.ran ? 'PASS' : 'FAIL'}  ${m.owner.grep ?? m.owner.name}`)
  if (!(r.passed && r.ran)) console.log(r.out.slice(-1500))
}

// ── Phase 2: one mutation at a time, restored immediately. ─────────────────
for (const m of selected) {
  const rec = { id: m.id, what: m.what, file: m.file, owner: m.owner.grep ?? m.owner.name }
  const original = readFileSync(m.file, 'utf8')
  const count = original.split(m.anchor).length - 1
  if (count !== 1) {
    rec.result = 'ANCHOR NOT UNIQUE'
    rec.detail = `anchor occurs ${count} times`
    observed.mutations.push(rec)
    console.log(`${m.id} ${rec.result} (${count})`)
    continue
  }
  if (!ownersPassed.get(JSON.stringify(m.owner))) {
    rec.result = 'OWNER FAILED UNMUTATED'
    observed.mutations.push(rec)
    console.log(`${m.id} ${rec.result}`)
    continue
  }
  const mutated = original.replace(m.anchor, m.replace)
  writeFileSync(m.file, mutated)
  try {
    rec.fileChanged = readFileSync(m.file, 'utf8') !== original
    const b = build()
    if (!b.ok) {
      rec.result = 'DOES NOT BUILD'
      rec.detail = b.out.slice(-600)
    } else {
      rec.bundle = b.hash
      rec.bundleMoved = b.hash !== base.hash
      const r = runOwner(m.owner)
      rec.ownerRan = r.ran
      rec.ownerFailed = !r.passed
      if (r.infra) rec.result = 'INFRA ERROR (not a kill)'
      else if (!rec.fileChanged) rec.result = 'PATCH DID NOT APPLY'
      else if (m.owner.kind === 'e2e' && !rec.bundleMoved) rec.result = 'MUTATION NOT SERVED'
      else if (!r.ran) rec.result = 'OWNER DID NOT RUN'
      else rec.result = r.passed ? 'SURVIVED' : 'KILLED'
      if (rec.result !== 'KILLED') rec.detail = r.out.slice(-1200)
      else {
        const line = r.out.split('\n').find((l) => /Error:|Expected|toHave|toBe|toContain/.test(l))
        rec.failure = line?.trim()
      }
    }
  } finally {
    writeFileSync(m.file, original)
  }
  observed.mutations.push(rec)
  console.log(`${m.id} ${rec.result}  — ${m.what}${rec.failure ? `\n     ${rec.failure}` : ''}`)
}

// ── Phase 3: restored tree must rebuild to the baseline bundle. ─────────────
const after = build()
observed.restoredBundle = after.ok ? after.hash : 'DOES NOT BUILD'
observed.restoredMatchesBaseline = after.ok && after.hash === base.hash
observed.finishedAt = new Date().toISOString()
writeFileSync('.mutation/observed.json', JSON.stringify(observed, null, 2))

const killed = observed.mutations.filter((r) => r.result === 'KILLED').length
console.log(`\n${killed}/${observed.mutations.length} killed; restored bundle ${observed.restoredBundle} ${observed.restoredMatchesBaseline ? '= baseline' : '≠ BASELINE'}`)
try {
  execSync('git diff --quiet -- src', { stdio: 'ignore' })
} catch {
  console.error('WARNING: src/ differs from HEAD after restore')
  process.exitCode = 1
}
if (killed !== observed.mutations.length || !observed.restoredMatchesBaseline) process.exitCode = 1
