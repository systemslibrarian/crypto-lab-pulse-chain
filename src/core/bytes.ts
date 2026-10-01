/** Byte helpers shared by both beacons. Nothing here is cryptographic. */

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim()
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`not an even-length hex string (${clean.length} chars)`)
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16)
  return out
}

export function toHex(bytes: Uint8Array, upper = false): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return upper ? s.toUpperCase() : s
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Big-endian unsigned integer of `width` bytes (4 = uint32, 8 = uint64). */
export function beUint(value: number | bigint, width: number): Uint8Array {
  let v = BigInt(value)
  if (v < 0n || v >= 1n << BigInt(8 * width)) {
    throw new Error(`${value} does not fit in ${width} bytes`)
  }
  const out = new Uint8Array(width)
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0)
  return d === 0
}

export function os2ip(bytes: Uint8Array): bigint {
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}

export function i2osp(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  if (v !== 0n) throw new Error(`integer does not fit in ${len} bytes`)
  return out
}

/** Square-and-multiply. Only ever used on public values (RSA verify). */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n
  let b = base % mod
  let e = exp
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod
    b = (b * b) % mod
    e >>= 1n
  }
  return r
}

/** Shorten a long hex string for display: `ab12cd…ef34`. */
export function abbrev(hex: string, head = 8, tail = 6): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`
}
