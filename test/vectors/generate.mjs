// Regenerates vectors.json from the reference implementation:
//   cd test/vectors && npm i --no-save @ensdomains/address-encoder && node generate.mjs
import { writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { getCoderByCoinName } from '@ensdomains/address-encoder'
import { base58, bech32, bech32m, createBase58check } from '@scure/base'
import { sha256 } from '@noble/hashes/sha256'

const btc = getCoderByCoinName('btc')
const sol = getCoderByCoinName('sol')
const hex = (b) => '0x' + Buffer.from(b).toString('hex')
const cat = (...a) => Buffer.concat(a.map((x) => Buffer.from(x)))

// Bias some randomness towards leading zero bytes to exercise base58 '1' handling.
const rnd = (n) => {
  const b = randomBytes(n)
  const z = Math.random() < 0.2 ? Math.floor(Math.random() * 4) : 0
  b.fill(0, 0, Math.min(z, n))
  return b
}

const btcScripts = [
  cat([0x76, 0xa9, 0x14], Buffer.alloc(20), [0x88, 0xac]),
  cat([0x76, 0xa9, 0x14], Buffer.alloc(20, 0xff), [0x88, 0xac]),
  cat([0xa9, 0x14], Buffer.alloc(20), [0x87]),
]
for (let i = 0; i < 20; i++) {
  btcScripts.push(cat([0x76, 0xa9, 0x14], rnd(20), [0x88, 0xac]))
  btcScripts.push(cat([0xa9, 0x14], rnd(20), [0x87]))
  btcScripts.push(cat([0x00, 20], rnd(20)))
  btcScripts.push(cat([0x00, 32], rnd(32)))
  btcScripts.push(cat([0x51, 32], rnd(32)))
  const v = 1 + Math.floor(Math.random() * 16)
  const len = 2 + Math.floor(Math.random() * 39)
  btcScripts.push(cat([0x50 + v, len], rnd(len)))
}

const solKeys = [Buffer.alloc(32), Buffer.alloc(32, 0xff)]
for (let i = 0; i < 40; i++) solKeys.push(rnd(32))

const b58c = createBase58check(sha256)
const p20 = rnd(20)
const p32 = rnd(32)
const v0 = btc.encode(cat([0x00, 20], p20))
const flip = (a) => a.slice(0, -1) + (a.at(-1) === 'q' ? 'p' : 'q')

// Addresses every implementation must reject. `reason` is informational.
const invalidBtc = [
  ['bad base58 checksum', flip(btc.encode(cat([0x76, 0xa9, 0x14], p20, [0x88, 0xac])))],
  ['unknown base58 version (testnet p2pkh)', b58c.encode(cat([0x6f], p20))],
  ['base58 payload too long', b58c.encode(cat([0x00], p20, [0x00]))],
  ['base58 payload too short', b58c.encode(cat([0x00], p20.subarray(0, 19)))],
  ['base58 invalid char 0', '0' + btc.encode(cat([0x76, 0xa9, 0x14], p20, [0x88, 0xac])).slice(1)],
  ['base58 invalid char l', btc.encode(cat([0xa9, 0x14], p20, [0x87])).slice(0, -1) + 'l'],
  ['empty', ''],
  ['bad bech32 checksum', flip(v0)],
  ['mixed case bech32', v0.slice(0, 10).toUpperCase() + v0.slice(10)],
  ['wrong hrp', bech32.encode('tb', [0, ...bech32.toWords(p20)])],
  ['v0 with bech32m checksum', bech32m.encode('bc', [0, ...bech32m.toWords(p20)])],
  ['v1 with bech32 checksum', bech32.encode('bc', [1, ...bech32.toWords(p32)])],
  ['v0 program 21 bytes', bech32.encode('bc', [0, ...bech32.toWords(rnd(21))])],
  ['v1 program 1 byte', bech32m.encode('bc', [1, ...bech32m.toWords(rnd(1))])],
  ['v1 program 41 bytes', bech32m.encode('bc', [1, ...bech32m.toWords(rnd(41))])],
  ['witness version 17', bech32m.encode('bc', [17, ...bech32m.toWords(p32)])],
  ['non-zero padding', bech32.encode('bc', [0, ...bech32.toWords(p32).slice(0, -1), bech32.toWords(p32).at(-1) | 1])],
  ['padding > 4 bits', bech32.encode('bc', [0, ...bech32.toWords(p20), 0])],
  ['bech32 invalid char b', v0.slice(0, 6) + 'b' + v0.slice(7)],
  ['no data', bech32.encode('bc', [])],
]

// Scripts the encoder must reject.
const invalidBtcScripts = [
  ['empty', Buffer.alloc(0)],
  ['p2pkh wrong length', cat([0x76, 0xa9, 0x15], rnd(21), [0x88, 0xac])],
  ['p2pkh wrong opcode', cat([0x76, 0xa9, 0x14], p20, [0x88, 0xad])],
  ['p2sh wrong length', cat([0xa9, 0x15], rnd(21), [0x87])],
  ['p2sh wrong opcode', cat([0xa9, 0x14], p20, [0x88])],
  ['segwit push length mismatch', cat([0x00, 21], p20)],
  ['segwit v0 bad program length', cat([0x00, 21], rnd(21))],
  ['segwit program too long', cat([0x51, 41], rnd(41))],
  ['segwit program too short', cat([0x51, 1], rnd(1))],
  ['OP_RETURN', cat([0x6a, 4], rnd(4))],
]

const invalidSol = [
  ['31 bytes', base58.encode(cat([0x01], rnd(30)))],
  ['33 bytes', base58.encode(cat([0x01], rnd(32)))],
  ['invalid char 0', '0' + sol.encode(rnd(32)).slice(1)],
  ['invalid char O', sol.encode(rnd(32)).slice(0, -1) + 'O'],
  ['too short', '1111111111111111111111111111111'],
  ['too long', '1'.repeat(45)],
  ['empty', ''],
]

const vectors = {
  invalidBtc: invalidBtc.map(([reason, address]) => ({ address, reason })),
  invalidBtcScripts: invalidBtcScripts.map(([reason, b]) => ({ bytes: hex(b), reason })),
  invalidSol: invalidSol.map(([reason, address]) => ({ address, reason })),
  btc: btcScripts.map((s) => {
    const address = btc.encode(s)
    if (hex(btc.decode(address)) !== hex(s)) throw new Error('btc roundtrip')
    return { address, bytes: hex(s) }
  }),
  sol: solKeys.map((k) => {
    const address = sol.encode(k)
    return { address, bytes: hex(k) }
  }),
}
for (const { address, reason } of vectors.invalidBtc) {
  let ok = true
  try { btc.decode(address) } catch { ok = false }
  if (ok) console.warn(`note: reference accepts invalid btc (${reason}): ${address}`)
}
for (const { address, reason } of vectors.invalidSol) {
  let ok = true
  try { sol.decode(address) } catch { ok = false }
  if (ok) throw new Error(`reference accepts invalid sol (${reason})`)
}
// forge's JSON cheatcodes don't support `[*]`, so store columns: { addresses: [...], bytes: [...] }
const columns = Object.fromEntries(
  Object.entries(vectors).map(([k, rows]) => [
    k,
    Object.fromEntries(Object.keys(rows[0]).map((f) => [f, rows.map((r) => r[f])])),
  ]),
)
writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(columns, null, 2) + '\n')
console.log(Object.entries(vectors).map(([k, v]) => `${k}: ${v.length}`).join(', '))
