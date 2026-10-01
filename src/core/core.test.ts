import { describe, expect, it } from 'vitest'
import { beUint, bytesEqual, concat, fromHex, i2osp, modPow, os2ip, toHex } from './bytes'
import { readTlv } from './der'

describe('bytes', () => {
  it('hex round-trips and rejects odd or non-hex input', () => {
    expect(toHex(fromHex('00ff7A'))).toBe('00ff7a')
    expect(() => fromHex('abc')).toThrow()
    expect(() => fromHex('zz')).toThrow()
  })

  it('beUint encodes big-endian and refuses overflow', () => {
    expect(toHex(beUint(64, 4))).toBe('00000040')
    expect(toHex(beUint(64, 8))).toBe('0000000000000040')
    expect(() => beUint(256, 1)).toThrow()
  })

  it('os2ip / i2osp are inverse', () => {
    const b = fromHex('0102030405')
    expect(toHex(i2osp(os2ip(b), 5))).toBe('0102030405')
    expect(() => i2osp(256n, 1)).toThrow()
  })

  it('modPow matches a small known case', () => {
    expect(modPow(4n, 13n, 497n)).toBe(445n)
  })

  it('concat and bytesEqual', () => {
    expect(bytesEqual(concat(fromHex('01'), fromHex('0203')), fromHex('010203'))).toBe(true)
    expect(bytesEqual(fromHex('01'), fromHex('0102'))).toBe(false)
  })
})

describe('DER reader', () => {
  it('reads short and long-form lengths', () => {
    expect(readTlv(fromHex('0403aabbcc'), 0)).toEqual({ tag: 4, start: 0, valueStart: 2, end: 5 })
    const long = fromHex('0481' + '80' + '00'.repeat(128))
    expect(readTlv(long, 0).end).toBe(131)
  })

  it('fails closed on truncation and indefinite length', () => {
    expect(() => readTlv(fromHex('0405aabb'), 0)).toThrow(/past the buffer/)
    expect(() => readTlv(fromHex('3080'), 0)).toThrow(/indefinite/)
  })
})
