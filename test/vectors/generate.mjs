// Regenerates vectors.json from the reference implementation:
//   cd test/vectors && npm i --no-save @ensdomains/address-encoder && node generate.mjs
//
// Output, per coin (column-oriented, since forge's JSON cheatcodes don't support `[*]`):
//   { "<coin>": { "coinType": n,
//                 "valid":          { "address": [...], "bytes": [...] },
//                 "decodeOnly":     { "address": [...], "bytes": [...] },    // decode only (non-canonical forms)
//                 "invalidAddress": { "address": [...], "reason": [...] },   // decode must revert
//                 "invalidBytes":   { "bytes": [...],   "reason": [...] } } } // encode must revert
import { writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { getCoderByCoinName } from '@ensdomains/address-encoder'
import { base58, base58xrp, base32, bech32, bech32m, createBase58check, utils } from '@scure/base'
import { encodeBchAddressWithVersion, crc32 } from '@ensdomains/address-encoder/utils'
import { blake2b } from '@noble/hashes/blake2b'
import { encode as cborEncode, Tagged } from 'cborg'
import { sha256 } from '@noble/hashes/sha256'

const hex = (b) => '0x' + Buffer.from(b).toString('hex')
const cat = (...a) => Buffer.concat(a.map((x) => Buffer.from(x)))
const b58c = createBase58check(sha256)
const flip = (a) => a.slice(0, -1) + (a.at(-1) === 'q' ? 'p' : 'q')
const times = (n, f) => Array.from({ length: n }, f)

// Bias some randomness towards leading zero bytes to exercise base58 '1' handling.
const rnd = (n) => {
  const b = randomBytes(n)
  const z = Math.random() < 0.2 ? Math.floor(Math.random() * 4) : 0
  b.fill(0, 0, Math.min(z, n))
  return b
}
const p2pkh = (h) => cat([0x76, 0xa9, 0x14], h, [0x88, 0xac])
const p2sh = (h) => cat([0xa9, 0x14], h, [0x87])
const p20 = rnd(20)
const p32 = rnd(32)

const coins = {}
const define = (name, { valid, decodeOnly = [], invalidAddress, invalidBytes }) => {
  const coder = getCoderByCoinName(name)
  coins[name] = {
    coinType: coder.coinType,
    valid: valid.map((b) => {
      const address = coder.encode(b)
      if (name === 'ada' && b[0] !== 0x83 && !address.startsWith('addr1')) throw new Error('ada shelley encoded as byron')
      if (hex(coder.decode(address)) !== hex(b)) throw new Error(`${name} roundtrip`)
      return { address, bytes: hex(b) }
    }),
    decodeOnly: decodeOnly.map((address) => ({ address, bytes: hex(coder.decode(address)) })),
    invalidAddress: invalidAddress.map(([reason, address]) => {
      let accepted = true
      try { coder.decode(address) } catch { accepted = false }
      if (accepted) console.warn(`note: reference accepts invalid ${name} (${reason}): ${address}`)
      return { address, reason }
    }),
    invalidBytes: invalidBytes.map(([reason, b]) => ({ bytes: hex(b), reason })),
  }
}

// ------------------------------------------------------------------ btc

const btc = getCoderByCoinName('btc')
const btcV0 = btc.encode(cat([0x00, 20], p20))
define('btc', {
  valid: [
    p2pkh(Buffer.alloc(20)),
    p2pkh(Buffer.alloc(20, 0xff)),
    p2sh(Buffer.alloc(20)),
    ...times(20, () => {
      const v = 1 + Math.floor(Math.random() * 16)
      const len = 2 + Math.floor(Math.random() * 39)
      return [
        p2pkh(rnd(20)),
        p2sh(rnd(20)),
        cat([0x00, 20], rnd(20)),
        cat([0x00, 32], rnd(32)),
        cat([0x51, 32], rnd(32)),
        cat([0x50 + v, len], rnd(len)),
      ]
    }).flat(),
  ],
  invalidAddress: [
    ['bad base58 checksum', flip(btc.encode(p2pkh(p20)))],
    ['unknown base58 version (testnet p2pkh)', b58c.encode(cat([0x6f], p20))],
    ['base58 payload too long', b58c.encode(cat([0x00], p20, [0x00]))],
    ['base58 payload too short', b58c.encode(cat([0x00], p20.subarray(0, 19)))],
    ['base58 invalid char 0', '0' + btc.encode(p2pkh(p20)).slice(1)],
    ['base58 invalid char l', btc.encode(p2sh(p20)).slice(0, -1) + 'l'],
    ['empty', ''],
    ['bad bech32 checksum', flip(btcV0)],
    ['mixed case bech32', btcV0.slice(0, 10).toUpperCase() + btcV0.slice(10)],
    ['wrong hrp', bech32.encode('tb', [0, ...bech32.toWords(p20)])],
    ['v0 with bech32m checksum', bech32m.encode('bc', [0, ...bech32m.toWords(p20)])],
    ['v1 with bech32 checksum', bech32.encode('bc', [1, ...bech32.toWords(p32)])],
    ['v0 program 21 bytes', bech32.encode('bc', [0, ...bech32.toWords(rnd(21))])],
    ['v1 program 1 byte', bech32m.encode('bc', [1, ...bech32m.toWords(rnd(1))])],
    ['v1 program 41 bytes', bech32m.encode('bc', [1, ...bech32m.toWords(rnd(41))])],
    ['witness version 17', bech32m.encode('bc', [17, ...bech32m.toWords(p32)])],
    ['non-zero padding', bech32.encode('bc', [0, ...bech32.toWords(p32).slice(0, -1), bech32.toWords(p32).at(-1) | 1])],
    ['padding > 4 bits', bech32.encode('bc', [0, ...bech32.toWords(p20), 0])],
    ['bech32 invalid char b', btcV0.slice(0, 6) + 'b' + btcV0.slice(7)],
    ['no data', bech32.encode('bc', [])],
  ],
  invalidBytes: [
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
  ],
})

// ------------------------------------------------------------------ doge

const doge = getCoderByCoinName('doge')
define('doge', {
  valid: [
    p2pkh(Buffer.alloc(20)),
    p2pkh(Buffer.alloc(20, 0xff)),
    p2sh(Buffer.alloc(20)),
    p2sh(Buffer.alloc(20, 0xff)),
    ...times(20, () => [p2pkh(rnd(20)), p2sh(rnd(20))]).flat(),
  ],
  invalidAddress: [
    ['bad base58 checksum', flip(doge.encode(p2pkh(p20)))],
    ['bitcoin p2pkh version', b58c.encode(cat([0x00], p20))],
    ['bitcoin p2sh version', b58c.encode(cat([0x05], p20))],
    ['testnet p2pkh version', b58c.encode(cat([0x71], p20))],
    ['base58 payload too long', b58c.encode(cat([0x1e], p20, [0x00]))],
    ['base58 payload too short', b58c.encode(cat([0x1e], p20.subarray(0, 19)))],
    ['base58 invalid char I', doge.encode(p2pkh(p20)).slice(0, -1) + 'I'],
    ['bech32 (no segwit on doge)', bech32.encode('doge', [0, ...bech32.toWords(p20)])],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['p2pkh wrong length', cat([0x76, 0xa9, 0x15], rnd(21), [0x88, 0xac])],
    ['p2sh wrong opcode', cat([0xa9, 0x14], p20, [0x88])],
    ['segwit v0 (no segwit on doge)', cat([0x00, 20], p20)],
    ['segwit v1 (no segwit on doge)', cat([0x51, 32], p32)],
    ['OP_RETURN', cat([0x6a, 4], rnd(4))],
  ],
})

// ------------------------------------------------------------------ sol

const sol = getCoderByCoinName('sol')
define('sol', {
  valid: [Buffer.alloc(32), Buffer.alloc(32, 0xff), ...times(40, () => rnd(32))],
  invalidAddress: [
    ['31 bytes', base58.encode(cat([0x01], rnd(30)))],
    ['33 bytes', base58.encode(cat([0x01], rnd(32)))],
    ['invalid char 0', '0' + sol.encode(rnd(32)).slice(1)],
    ['invalid char O', sol.encode(rnd(32)).slice(0, -1) + 'O'],
    ['too short', '1'.repeat(31)],
    ['too long', '1'.repeat(45)],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['31 bytes', rnd(31)],
    ['33 bytes', rnd(33)],
  ],
})

// ------------------------------------------------------------------ xch

const xch = getCoderByCoinName('xch')
const xchAddr = xch.encode(p32)
const xchWords = bech32m.toWords(p32)
define('xch', {
  valid: [Buffer.alloc(32), Buffer.alloc(32, 0xff), ...times(40, () => rnd(32))],
  invalidAddress: [
    ['bad checksum', flip(xchAddr)],
    ['mixed case', xchAddr.slice(0, 10).toUpperCase() + xchAddr.slice(10)],
    ['testnet hrp', bech32m.encode('txch', xchWords)],
    ['bech32 checksum', bech32.encode('xch', xchWords)],
    ['31 bytes', bech32m.encode('xch', bech32m.toWords(rnd(31)))],
    ['33 bytes', bech32m.encode('xch', bech32m.toWords(rnd(33)))],
    ['non-zero padding', bech32m.encode('xch', [...xchWords.slice(0, -1), xchWords.at(-1) | 1])],
    ['invalid char b', xchAddr.slice(0, 8) + 'b' + xchAddr.slice(9)],
    ['no data', bech32m.encode('xch', [])],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['31 bytes', rnd(31)],
    ['33 bytes', rnd(33)],
  ],
})

// ------------------------------------------------------------------ ltc

const ltc = getCoderByCoinName('ltc')
define('ltc', {
  valid: [
    ...times(10, () => [
      p2pkh(rnd(20)),
      p2sh(rnd(20)),
      cat([0x00, 20], rnd(20)),
      cat([0x00, 32], rnd(32)),
      cat([0x51, 32], rnd(32)),
    ]).flat(),
  ],
  // Legacy P2SH ("3...", version 0x05) decodes, but encodes as "M..." (0x32).
  decodeOnly: [
    ...times(5, () => b58c.encode(cat([0x05], rnd(20)))),
    ltc.encode(cat([0x00, 20], p20)).toUpperCase(),
  ],
  invalidAddress: [
    ['bad base58 checksum', flip(ltc.encode(p2pkh(p20)))],
    ['bitcoin p2pkh version', b58c.encode(cat([0x00], p20))],
    ['bitcoin segwit hrp', btc.encode(cat([0x00, 20], p20))],
    ['v0 with bech32m checksum', bech32m.encode('ltc', [0, ...bech32m.toWords(p20)])],
    ['bad bech32 checksum', flip(ltc.encode(cat([0x00, 20], p20)))],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['segwit v0 bad program length', cat([0x00, 21], rnd(21))],
    ['OP_RETURN', cat([0x6a, 4], rnd(4))],
  ],
})

// ------------------------------------------------------------------ bch

const bch = getCoderByCoinName('bch')
const bchAddr = bch.encode(p2pkh(p20))
define('bch', {
  valid: [
    p2pkh(Buffer.alloc(20)),
    p2sh(Buffer.alloc(20, 0xff)),
    ...times(15, () => [p2pkh(rnd(20)), p2sh(rnd(20))]).flat(),
  ],
  decodeOnly: [
    b58c.encode(cat([0x00], rnd(20))),
    b58c.encode(cat([0x05], rnd(20))),
    bchAddr.slice('bitcoincash:'.length),
    bchAddr.toUpperCase(),
    bch.encode(p2sh(p20)).slice('bitcoincash:'.length).toUpperCase(),
  ],
  invalidAddress: [
    ['bad checksum', flip(bchAddr)],
    ['mixed case', bchAddr.slice(0, 16).toUpperCase() + bchAddr.slice(16)],
    ['wrong prefix', 'bchtest:' + bchAddr.slice('bitcoincash:'.length)],
    ['unknown type 2', encodeBchAddressWithVersion(16, p20)],
    ['p2sh32 (unsupported)', encodeBchAddressWithVersion(8, p32)],
    ['bad base58 checksum', flip(b58c.encode(cat([0x00], p20)))],
    ['base58 unknown version', b58c.encode(cat([0x6f], p20))],
    ['invalid char b', bchAddr.slice(0, 14) + 'b' + bchAddr.slice(15)],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['segwit', cat([0x00, 20], p20)],
    ['p2pkh wrong length', cat([0x76, 0xa9, 0x15], rnd(21), [0x88, 0xac])],
    ['OP_RETURN', cat([0x6a, 4], rnd(4))],
  ],
})

// ------------------------------------------------------------------ xrp

const xrp = getCoderByCoinName('xrp')
const xrpCheck = utils.chain(utils.checksum(4, (d) => sha256(sha256(d))), base58xrp)
define('xrp', {
  valid: [cat([0x00], Buffer.alloc(20)), cat([0x00], Buffer.alloc(20, 0xff)), ...times(30, () => cat([0x00], rnd(20)))],
  invalidAddress: [
    ['bad checksum', flip(xrp.encode(cat([0x00], p20)))],
    ['bitcoin alphabet', b58c.encode(cat([0x00], p20))],
    ['wrong version', xrpCheck.encode(cat([0x05], p20))],
    ['payload too long', xrpCheck.encode(cat([0x00], p20, [0x00]))],
    ['payload too short', xrpCheck.encode(cat([0x00], p20.subarray(0, 19)))],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['20 bytes', p20],
    ['wrong version', cat([0x05], p20)],
  ],
})

// ------------------------------------------------------------------ atom

const atom = getCoderByCoinName('atom')
const atomAddr = atom.encode(p20)
define('atom', {
  valid: [...times(15, () => rnd(20)), ...times(15, () => rnd(32))],
  invalidAddress: [
    ['bad checksum', flip(atomAddr)],
    ['mixed case', atomAddr.slice(0, 10).toUpperCase() + atomAddr.slice(10)],
    ['wrong hrp', bech32.encode('osmo', bech32.toWords(p20))],
    ['bech32m checksum', bech32m.encode('cosmos', bech32m.toWords(p20))],
    ['no data', bech32.encode('cosmos', [])],
    ['empty', ''],
  ],
  invalidBytes: [['empty', Buffer.alloc(0)]],
})

// ------------------------------------------------------------------ trx

const trx = getCoderByCoinName('trx')
define('trx', {
  valid: [cat([0x41], Buffer.alloc(20)), ...times(30, () => cat([0x41], rnd(20)))],
  invalidAddress: [
    ['bad checksum', flip(trx.encode(cat([0x41], p20)))],
    ['wrong version', b58c.encode(cat([0x00], p20))],
    ['payload too long', b58c.encode(cat([0x41], p20, [0x00]))],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['wrong version', cat([0x00], p20)],
    ['20 bytes', p20],
  ],
})

// ------------------------------------------------------------------ xlm

const xlm = getCoderByCoinName('xlm')
const crc16 = (d) => {
  let crc = 0
  for (const b of d) {
    crc ^= b << 8
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff
  }
  return [crc & 0xff, crc >> 8]
}
const strkey = (version, key) => base32.encode(cat([version], key, crc16(cat([version], key))))
const xlmAddr = xlm.encode(p32)
define('xlm', {
  valid: [Buffer.alloc(32), Buffer.alloc(32, 0xff), ...times(30, () => rnd(32))],
  invalidAddress: [
    ['bad checksum', xlmAddr.slice(0, -2) + (xlmAddr.at(-2) === 'A' ? 'B' : 'A') + xlmAddr.at(-1)],
    ['secret seed version', strkey(0x90, p32)],
    ['lowercase', xlmAddr.toLowerCase()],
    ['31-byte key', strkey(0x30, rnd(31))],
    ['invalid char 1', xlmAddr.slice(0, 10) + '1' + xlmAddr.slice(11)],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['31 bytes', rnd(31)],
    ['33 bytes', rnd(33)],
  ],
})

// ------------------------------------------------------------------ dot / ksm

const ss58 = (prefix, key, tweak = 0) => {
  const body = cat([prefix], key)
  const sum = blake2b(cat(Buffer.from('SS58PRE'), body)).slice(0, 2)
  sum[0] ^= tweak
  return base58.encode(cat(body, sum))
}
for (const [name, prefix, other] of [['dot', 0, 2], ['ksm', 2, 0]]) {
  define(name, {
    valid: [Buffer.alloc(32), Buffer.alloc(32, 0xff), ...times(30, () => rnd(32))],
    invalidAddress: [
      ['bad checksum', ss58(prefix, p32, 1)],
      ['other network prefix', ss58(other, p32)],
      ['generic substrate prefix 42', ss58(42, p32)],
      ['31-byte account', ss58(prefix, rnd(31))],
      ['33-byte account', ss58(prefix, rnd(33))],
      ['invalid char 0', '0' + ss58(prefix, p32).slice(1)],
      ['empty', ''],
    ],
    invalidBytes: [
      ['empty', Buffer.alloc(0)],
      ['31 bytes', rnd(31)],
      ['33 bytes', rnd(33)],
    ],
  })
}

// ------------------------------------------------------------------ ada

const ada = getCoderByCoinName('ada')
const icarus = () => cat([0x83, 0x58, 0x1c], rnd(28), [0xa0, 0x00])
const daedalus = () => cat([0x83, 0x58, 0x1c], rnd(28), [0xa1, 0x01, 0x58, 0x1e, 0x58, 0x1c], rnd(28), [0x00])
const byronRaw = (payload, crc = crc32(payload)) => base58.encode(cborEncode([new Tagged(24, payload), crc]))
const shelleyBase = cat([0x01], rnd(56))
// Reference quirk: `ada.encode` tries Byron first and accepts any output starting "Ae2"/"Ddz",
// so a 33-byte Shelley pointer address comes out as a bogus Byron address.
{
  const pointer33 = cat([0x41], rnd(28), [0x81, 0x00, 0x02, 0x03])
  if (!ada.encode(pointer33).startsWith('Ae2')) throw new Error('ada quirk no longer reproduces')
  console.warn('note: reference encodes 33-byte ada pointer addresses as Byron')
}
define('ada', {
  valid: [
    ...times(10, () => [
      cat([0x01], rnd(56)), // base, key/key
      cat([0x31], rnd(56)), // base, script/script
      cat([0x61], rnd(28)), // enterprise, key
      cat([0x71], rnd(28)), // enterprise, script
      // pointer (34 bytes: the reference encodes any 33-byte input as Byron "Ae2...")
      cat([0x41], rnd(28), [0x81, 0x80, 0x00, 0x02, 0x03]),
      icarus(),
      daedalus(),
    ]).flat(),
  ],
  decodeOnly: [ada.encode(shelleyBase).toUpperCase()],
  invalidAddress: [
    ['bad bech32 checksum', flip(ada.encode(shelleyBase))],
    ['testnet network id', bech32.encode('addr', bech32.toWords(cat([0x00], rnd(56))), 104)],
    ['testnet hrp', bech32.encode('addr_test', bech32.toWords(cat([0x00], rnd(56))), 110)],
    ['base address 56 bytes', bech32.encode('addr', bech32.toWords(cat([0x01], rnd(55))), 104)],
    ['enterprise 30 bytes', bech32.encode('addr', bech32.toWords(cat([0x61], rnd(29))), 104)],
    ['reward address under addr hrp', bech32.encode('addr', bech32.toWords(cat([0xe1], rnd(28))), 104)],
    ['bech32m checksum', bech32m.encode('addr', bech32m.toWords(shelleyBase), 104)],
    ['byron bad crc', byronRaw(icarus(), 1234)],
    ['byron not tagged', base58.encode(cborEncode([icarus(), crc32(icarus())]))],
    ['byron inner not an address', byronRaw(cat([0x82], rnd(30)))],
    ['empty', ''],
  ],
  invalidBytes: [
    ['empty', Buffer.alloc(0)],
    ['testnet network id', cat([0x00], rnd(56))],
    ['base address 56 bytes', cat([0x01], rnd(55))],
    ['enterprise 30 bytes', cat([0x61], rnd(29))],
    ['pointer too short', cat([0x41], rnd(28), [0x00, 0x00])],
    ['reward address', cat([0xe1], rnd(28))],
    ['header type 9', cat([0x91], rnd(28))],
  ],
})

// ------------------------------------------------------------------ eth / evm (ENSIP-19)

const eth = getCoderByCoinName('eth')
const ethAddr = eth.encode(p20)
const flipCase = (a) => {
  const i = [...a].findIndex((c, j) => j > 1 && /[a-fA-F]/.test(c))
  const c = a[i]
  return a.slice(0, i) + (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) + a.slice(i + 1)
}
for (const name of ['eth', 'op']) {
  define(name, {
    valid: [Buffer.alloc(20), Buffer.alloc(20, 0xff), ...times(30, () => rnd(20))],
    decodeOnly: [ethAddr.toLowerCase(), '0x' + ethAddr.slice(2).toUpperCase()],
    invalidAddress: [
      ['bad checksum', flipCase(ethAddr)],
      ['no 0x prefix', ethAddr.slice(2)],
      ['0X prefix', '0X' + ethAddr.slice(2)],
      ['39 hex digits', ethAddr.slice(0, -1)],
      ['41 hex digits', ethAddr + 'a'],
      ['non-hex char', ethAddr.slice(0, -1) + 'g'],
      ['empty', ''],
    ],
    invalidBytes: [
      ['empty', Buffer.alloc(0)],
      ['19 bytes', rnd(19)],
      ['21 bytes', rnd(21)],
      ['32 bytes', rnd(32)],
    ],
  })
}

// ------------------------------------------------------------------ write

const columns = (rows, fields) => Object.fromEntries(fields.map((f) => [f, rows.map((r) => r[f])]))
const out = Object.fromEntries(
  Object.entries(coins).map(([name, c]) => [
    name,
    {
      coinType: c.coinType,
      valid: columns(c.valid, ['address', 'bytes']),
      decodeOnly: columns(c.decodeOnly, ['address', 'bytes']),
      invalidAddress: columns(c.invalidAddress, ['address', 'reason']),
      invalidBytes: columns(c.invalidBytes, ['bytes', 'reason']),
    },
  ]),
)
writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n')
for (const [name, c] of Object.entries(coins)) {
  console.log(`${name}: ${c.valid.length} valid, ${c.decodeOnly.length} decode-only, ${c.invalidAddress.length} invalid addresses, ${c.invalidBytes.length} invalid bytes`)
}
