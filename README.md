# address-coder-sol

[![CI](https://github.com/ensdomains/address-coder-sol/actions/workflows/test.yml/badge.svg)](https://github.com/ensdomains/address-coder-sol/actions/workflows/test.yml)

Solidity port of [ensdomains/address-encoder](https://github.com/ensdomains/address-encoder): convert
human-readable chain addresses to and from the binary form ENS stores in `addr(node, coinType)`.

| Library            | coinType | Address                                  | Bytes                                     |
| ------------------ | -------- | ---------------------------------------- | ----------------------------------------- |
| `BitcoinCoder`     | 0        | `1…` / `3…` / `bc1…`                     | scriptPubKey                              |
| `LitecoinCoder`    | 2        | `L…` / `M…` / `3…`¹ / `ltc1…`            | scriptPubKey                              |
| `DogecoinCoder`    | 3        | `D…` / `9…` / `A…`                       | scriptPubKey                              |
| `CosmosCoder`      | 118      | `cosmos1…` (bech32)                      | account bytes                             |
| `XrpCoder`         | 144      | `r…` (classic)                           | `0x00` ‖ 20-byte account ID               |
| `BitcoinCashCoder` | 145      | `bitcoincash:q…` / `p…`, `1…`¹ / `3…`¹   | scriptPubKey (P2PKH / P2SH)               |
| `StellarCoder`     | 148      | `G…`                                     | 32-byte ed25519 key                       |
| `TronCoder`        | 195      | `T…`                                     | `0x41` ‖ 20-byte account                  |
| `PolkadotCoder`    | 354      | `1…` (SS58 prefix 0)²                    | 32-byte account ID                        |
| `KusamaCoder`      | 434      | SS58 prefix 2²                           | 32-byte account ID                        |
| `SolanaCoder`      | 501      | base58                                   | 32-byte public key                        |
| `CardanoCoder`     | 1815     | `addr1…` (Shelley), `Ae2…` / `Ddz…` (Byron) | CIP-19 address bytes / Byron CBOR address |
| `ChiaCoder`        | 8444     | `xch1…` (bech32m)                        | 32-byte puzzle hash                       |

Each library has `encode(bytes) → string`, `decode(string) → bytes` and a `COIN_TYPE` constant.

¹ Decode only: `encode` emits the canonical form (`M…` for LTC P2SH, `bitcoincash:…` for BCH). BCH
  also accepts CashAddr without the `bitcoincash:` prefix.<br>
² `view`, not `pure`: the SS58 checksum uses the EIP-152 BLAKE2b precompile (`0x09`), which some
  L2s / zkEVMs don't implement.

```solidity
import {BitcoinCoder} from "address-coder-sol/BitcoinCoder.sol";

bytes memory script = BitcoinCoder.decode("bc1q...");   // 0x0014...
string memory addr  = BitcoinCoder.encode(script);
```

Each coder is its own library of `internal` functions, so only what you call is compiled into your
contract. Each coder adds about 1–3.5 KB per direction; for example, `SolanaCoder.decode` alone is
~1.3 KB and pulls in none of the Bitcoin, bech32 or encode code.

Reusable building blocks live in `src/utils`:

- `Base58`: base58 and Base58Check, with the Bitcoin alphabet or a custom one
- `Base32`: unpadded RFC 4648 base32
- `Bech32`: bech32 / bech32m (BIP-173 / BIP-350) with an optional length limit, plus SegWit helpers
- `BitcoinLike`: P2PKH / P2SH / SegWit, parameterised by HRP and version bytes (including an extra
  decode-only P2SH version). `encodeLegacy` / `decodeLegacy` serve chains without SegWit and keep
  bech32 out of the bytecode.
- `CashAddr`: Bitcoin Cash address format
- `Blake2b`: BLAKE2b-512 using the EIP-152 precompile
- `SS58`: Substrate addresses (single-byte network prefixes)

Invalid input reverts with a custom error.

## Differences from the JS reference

Decoding is stricter than `@ensdomains/address-encoder` v3.0.0, which accepts these invalid
addresses:

- **BTC / LTC SegWit:** v0 with a bech32m checksum or v1+ with a bech32 checksum; witness programs
  outside 2–40 bytes; v0 programs that aren't 20 or 32 bytes; witness version > 16.
- **BTC / DOGE / TRX / XRP Base58Check:** payloads of the wrong length or with the wrong version byte.
- **Chia:** addresses that don't decode to exactly 32 bytes.
- **Cosmos:** empty account bytes.
- **Stellar:** keys that aren't 32 bytes.
- **Cardano:** Shelley addresses that aren't mainnet or that break CIP-19 lengths, reward addresses
  under the `addr` prefix, and Byron addresses whose inner bytes aren't a CBOR address (`0x83…`).

Encoding differs in a few places:

- **Cardano:** the reference encodes any 33-byte input as Byron, so 33-byte Shelley pointer addresses
  come out as bogus `Ae2…` strings. Here, header type 8 (`0x83…`) is Byron and everything else is
  Shelley (`addr1…`).
- **Bitcoin Cash:** P2SH32 (`bitcoincash:pv…`) is rejected. The reference decodes it to a malformed
  `a914 ‖ 32 bytes ‖ 87` script.
- **XRP:** only classic `r…` addresses are supported, not X-addresses.

## Development

Built with [Foundry](https://getfoundry.sh) using the [Solar](https://github.com/paradigmxyz/solar) compiler (`solc = "solar:0.3.1"`).

```bash
forge build
forge test
```

`test/vectors/vectors.json` is generated from the reference implementation:

```bash
cd test/vectors && npm i --no-save @ensdomains/address-encoder && node generate.mjs
```

## License

[MIT](LICENSE)
