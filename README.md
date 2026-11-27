# address-coder-sol

[![CI](https://github.com/ensdomains/address-coder-sol/actions/workflows/test.yml/badge.svg)](https://github.com/ensdomains/address-coder-sol/actions/workflows/test.yml)

Solidity port of [ensdomains/address-encoder](https://github.com/ensdomains/address-encoder): convert
human-readable chain addresses to and from the binary form ENS stores in `addr(node, coinType)`.

| Library        | coinType | `decode(string) → bytes`              | `encode(bytes) → string` |
| -------------- | -------- | ------------------------------------- | ------------------------ |
| `BitcoinCoder` | 0        | P2PKH / P2SH / SegWit v0–16 → scriptPubKey | scriptPubKey → address |
| `SolanaCoder`  | 501      | base58 → 32-byte public key           | 32-byte key → base58     |

```solidity
import {BitcoinCoder} from "address-coder-sol/BitcoinCoder.sol";

bytes memory script = BitcoinCoder.decode("bc1q...");   // 0x0014...
string memory addr  = BitcoinCoder.encode(script);
```

Each coder is its own library of `internal` functions, so only what you call is compiled into your
contract. For example, importing `SolanaCoder` and calling only `decode` adds ~1.3 KB and pulls in
none of the Bitcoin, bech32 or encode code.

Reusable building blocks live in `src/utils`:

- `Base58` — base58 and Base58Check
- `Bech32` — SegWit bech32 / bech32m (BIP-173 / BIP-350)
- `BitcoinLike` — parameterised by HRP and P2PKH/P2SH version bytes, for adding other Bitcoin-style chains

Invalid input reverts with a custom error.

## Differences from the JS reference

Decoding is stricter than `@ensdomains/address-encoder` v3.0.0, which accepts these invalid
addresses:

- SegWit v0 with a bech32m checksum, or v1+ with a bech32 checksum
- Witness programs outside 2–40 bytes, v0 programs that aren't 20 or 32 bytes, or witness version > 16
- Base58Check payloads that aren't exactly 21 bytes

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
