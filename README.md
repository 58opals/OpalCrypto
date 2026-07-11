# Opal Crypto

Status: v0.1.0 Developer Preview.

Opal Crypto is the lowest-level BCH cryptography package in the Swift stack. It exposes a strict, facade-first `OpalCrypto` namespace for keys, secp256k1 signatures, hashing, encoding, derivation, and numeric helpers without leaking implementation details into downstream code.

## Audience

Use Opal Crypto when you are building Swift BCH software and need stable cryptographic capabilities behind one public facade. Downstream code should integrate through `OpalCrypto` instead of depending on internal implementation types or source layout.

## Requirements

- Swift tools version: `6.2`
- Platforms:
  - `macOS 26`
  - `iOS 26`
  - `watchOS 26`
  - `tvOS 26`
  - `visionOS 26`

## Installation

The current public facade surface is available from the `v0.1.0` release.

```swift
dependencies: [
    .package(url: "https://github.com/58opals/OpalCrypto.git", from: "0.1.0")
]
```

Then add `"OpalCrypto"` to the target dependency list where you need it.

## Quick Start

```swift
import Foundation
import OpalCrypto

let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
let message = Data("opal-ecdsa-message".utf8)

let signature = try OpalCrypto.Signature.ECDSA.sign(
    message: message,
    privateKey: privateKey,
    format: .der
)
let isValid = try signature.verify(
    message: message,
    publicKey: publicKey
)
```

For Schnorr signatures, construct a `Signature.Digest`, then use `Signature.Schnorr.sign(digest:privateKey:)` and `signature.verify(digest:publicKey:)`. Hashing remains the caller's responsibility.

## Key Capabilities

- `Signature`: typed ECDSA and Schnorr signatures, 32-byte digests, verification keys, facade-owned formats, and nonce policies.
- `Secp256k1`: typed private keys, public keys, scalars, shared secrets, tweak-add, batch public-key derivation, and batch shared-secret derivation for higher-level scan workloads.
- `Key`: WIF, BIP-39 mnemonics, and extended private/public keys.
- `Hashing`: SHA-256, Hash256, Hash160, HMAC-SHA256, and HMAC-SHA512 helpers.
- `Encoding`: Base58 plus Bech32-style Base32 and polymod checksum primitives.
- `KeyDerivation`: PBKDF2 key derivation.
- `Numeric`: `UInt256`, `UInt512`, and `BigUnsignedInteger` facade wrappers.

The Base32 APIs use the Bech32 alphabet and stay intentionally low-level. Use `encodeBase32Bytes`/`decodeBase32Bytes` for byte-mode radix conversion and `Encoding.FiveBitValues` with `encodeBase32Values`/`decodeBase32Values` for five-bit symbol mode.

See [docs/public-api.md](docs/public-api.md) for the typed public facade shape.

## Boundaries

- In scope: facade-first BCH cryptography for keys, secp256k1, hashing, encoding, key derivation, and numeric primitives.
- Out of scope: wallet or app-domain orchestration, address management, RPA scan policy, network or protocol/runtime responsibilities, non-BCH features, non-Swift expansion, or reliance on internal implementation details as public API. Higher-level packages such as Opal Base own wallet-facing reusable payment address behavior; Opal Crypto only supplies the cryptographic computation primitives they need.

See [docs/engineering-principles.md](docs/engineering-principles.md) for the Swift-first implementation boundary, Apple-native acceleration policy, and benchmark-backed performance expectations. See [docs/performance-roadmap.md](docs/performance-roadmap.md) for the CPU-to-Metal optimization stages and [docs/metal-readiness.md](docs/metal-readiness.md) for the current Metal qualification boundary.

## Testing

```bash
swift test
```

For a quick release-mode performance smoke run:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite smoke
```

See [docs/benchmarks.md](docs/benchmarks.md) for benchmark suites, JSONL artifacts, and same-machine comparison guidance. See [docs/performance-roadmap.md](docs/performance-roadmap.md) for the staged performance roadmap.

## License

Opal Crypto is available under the [Apache License 2.0](LICENSE). Copyright 2026 58 Opals.

## Validation

Current correctness validation command:

```bash
swift test
```

Current benchmark smoke command:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite smoke
```

Correctness result: Passed on 2026-07-11 with 273 tests in 38 suites.

## Further Context

See [docs/context.md](docs/context.md) for package role, repo boundaries, and integration expectations.
