# Opal Crypto

Status: Developer Preview. The latest tag is `v0.2.0`. Secret-scalar operations have not completed constant-time hardening and security review; do not use this preview for production key handling.

Opal Crypto is the lowest-level BCH cryptography package in the Swift stack. It exposes a strict, facade-first `OpalCrypto` namespace for keys, secp256k1 signatures, hashing, encoding, derivation, and numeric helpers without leaking implementation details into downstream code.

## Audience

Use Opal Crypto when you are building or testing Swift BCH software and need typed cryptographic capabilities behind one public facade. Downstream code should integrate through `OpalCrypto` instead of depending on internal implementation types or source layout.

## Requirements

- Swift tools version: `6.2`
- Platforms:
  - `macOS 26`
  - `iOS 26`
  - `watchOS 26`
  - `tvOS 26`
  - `visionOS 26`

## Installation

The current public facade surface is available from the `v0.2.0` release.

```swift
dependencies: [
    .package(url: "https://github.com/58opals/OpalCrypto.git", from: "0.2.0")
]
```

Then add `"OpalCrypto"` to the target dependency list where you need it.

The `v0.2.0` release uses the stable `OpalDiagnostics` `v0.2.0` release, restoring version-based package installation. The historical `v0.1.3` manifest contains a branch-based `OpalDiagnostics` requirement and cannot be selected with a version-based package requirement.

## Quick Start

```swift
import Foundation
import OpalCrypto

let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
let message = Data("opal-ecdsa-message".utf8)

let signature = try OpalCrypto.Signature.ECDSA.signSHA256(
    message: message,
    privateKey: privateKey,
    format: .der
)
let isValid = try signature.verifySHA256(
    message: message,
    publicKey: publicKey
)
```

The explicit ECDSA message operations hash once with SHA-256. To supply a precomputed 32-byte digest without hashing it again, use `ECDSA.sign(digest:privateKey:)` and `signature.verify(digest:publicKey:)`. For Schnorr signatures, construct a `Signature.Digest`, then use `Signature.Schnorr.sign(digest:privateKey:)` and `signature.verify(digest:publicKey:)`; hashing remains the caller's responsibility.

## Key Capabilities

- `Signature`: typed ECDSA and Schnorr signatures, 32-byte digests, verification keys, facade-owned formats, nonce policies, and immutable BCH Schnorr verification batches.
- `Secp256k1`: typed private keys, public keys, scalars, legacy shared-secret digests, hardened shared-point x-coordinate derivation, tweak-add, batch public-key derivation, and batch shared-secret derivation for higher-level scan workloads.
- `Key`: WIF, BIP-39 mnemonics, extended private/public keys, and focused non-hardened BIP-32 child derivation from an explicit key and chain code.
- `Hashing`: SHA-256, Hash256, Hash160, HMAC-SHA256, and HMAC-SHA512 helpers.
- `Encoding`: Base58 plus Bech32-style Base32 and polymod checksum primitives, with explicit decoded-byte budgets.
- `KeyDerivation`: PBKDF2-HMAC-SHA-512 key derivation with a 64-byte default output and an explicit HMAC-work budget.
- `Numeric`: `UInt256`, `UInt512`, and budgeted `BigUnsignedInteger` facade wrappers.

The Base32 APIs use the Bech32 alphabet and stay intentionally low-level. Use nonthrowing `encodeBase32(bytes:)` with `decodeBase32Bytes(_:maximumDecodedByteCount:)` for byte-mode radix conversion, and `Encoding.FiveBitValues` with nonthrowing `encodeBase32(values:)` and `decodeBase32Values(_:)` for five-bit symbol mode. Base58 decoding offers `decodeBase58IfValid(_:maximumDecodedByteCount:)` for optional failure and `decodeBase58Validating(_:maximumDecodedByteCount:)` for an explicit error.

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

Correctness result: Passed on 2026-07-30 with 332 tests in 42 suites under both the normal and opt-in performance configurations.

## Further Context

See [docs/context.md](docs/context.md) for package role, repo boundaries, and integration expectations.
