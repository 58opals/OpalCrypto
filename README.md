# Opal Crypto

Status: Developer Preview. The latest tag is `v0.2.0`. Secret-scalar operations have not completed constant-time hardening and security review; do not use this preview for production key handling.

Opal Crypto is the lowest-level cryptography package in the Swift stack. It exposes a strict, facade-first `OpalCrypto` namespace for keys, BCH and BIP340 signatures, bounded RSA blind signatures, NIP-44 v2 encrypted payloads, authenticated encryption, hashing, secure random bytes, encoding, derivation, and numeric helpers without leaking implementation details into downstream code.

## Audience

Use Opal Crypto when you are building or testing Swift software that needs typed BCH or BIP340 cryptographic capabilities behind one public facade. Downstream code should integrate through `OpalCrypto` instead of depending on internal implementation types or source layout.

## Requirements

- Swift tools version: `6.4`
- Platforms:
  - `macOS 26`
  - `iOS 26`
  - `watchOS 26`
  - `tvOS 26`
  - `visionOS 26`
- Xcode's Metal Toolchain component. Install and verify it with:

  ```sh
  xcodebuild -downloadComponent MetalToolchain
  metal_path="$(/usr/bin/xcrun --toolchain MetalToolchain --find metal)"
  test -x "$metal_path"
  test -x "$(dirname "$metal_path")/metallib"
  ```

## Installation

Use the public `develop` branch for the current Swift 6.4 package stack:

```swift
dependencies: [
    .package(url: "https://github.com/58opals/OpalCrypto.git", branch: "develop")
]
```

Then add `"OpalCrypto"` to the target dependency list where you need it.

The published `v0.2.0` release remains available to version-based consumers and uses the stable `OpalDiagnostics` `v0.2.0` release. The historical `v0.1.3` manifest contains a branch-based `OpalDiagnostics` requirement and cannot be selected with a version-based package requirement. The current `develop` manifest instead follows `OpalDiagnostics` on `develop`; no new SemVer tag is implied.

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

The explicit ECDSA message operations hash once with SHA-256. To supply a precomputed 32-byte digest without hashing it again, use `ECDSA.sign(digest:privateKey:)` and `signature.verify(digest:publicKey:)`. For Bitcoin Cash Schnorr signatures, construct a `Signature.Digest`, then use `Signature.Schnorr.sign(digest:privateKey:)` and `signature.verify(digest:publicKey:)`; hashing remains the caller's responsibility. Genuine BIP340 is a separate `Signature.BIP340` API with a validated 32-byte x-only verification key and explicit 32-byte `AuxiliaryRandomness` supplied to `SigningKey.signBIP340(digest:auxiliaryRandomness:)`.

## Key Capabilities

- `Signature`: typed ECDSA, Bitcoin Cash Schnorr, and BIP340 signatures; 32-byte digests; SEC1 and x-only verification keys; facade-owned formats; nonce policies; and immutable BCH Schnorr verification batches.
- `RSABSSA`: RFC 9474 randomized RSA blind-signature preparation, blind signing, finalization, and verification for one strict RSA-2048/SHA-384/PSS profile, with opaque nonpersistent signing keys and RFC 9578-style public-key encoding.
- `Secp256k1`: typed private keys, public keys, scalars, legacy shared-secret digests, hardened shared-point x-coordinate derivation, tweak-add, batch public-key derivation, and batch shared-secret derivation for higher-level scan workloads.
- `SecureRandom`: operating-system secure random bytes behind an explicit `1...1024` allocation-safety boundary. This bound is an OpalCrypto resource limit, not a protocol constant.
- `Nostr.NIP44`: NIP-44 v2 conversation-key derivation, ChaCha20 encryption, HMAC-SHA256 authentication, standard padding, and canonical base64 payloads with explicit caller-owned resource limits.
- `AuthenticatedEncryption.AES256GCM`: typed 256-bit keys, 96-bit nonces, bounded combined sealed-box import, authenticated-data binding, and standard AES-GCM seal/open operations without exposing CryptoKit types.
- `Key`: WIF, BIP-39 mnemonics, extended private/public keys, and focused non-hardened BIP-32 child derivation from an explicit key and chain code.
- `Hashing`: SHA-256, Hash256, Hash160, HMAC-SHA256, and HMAC-SHA512 helpers.
- `Encoding`: Base58 plus Bech32-style Base32 and polymod checksum primitives, with explicit decoded-byte budgets.
- `KeyDerivation`: RFC 5869 HKDF-HMAC-SHA-256 plus PBKDF2-HMAC-SHA-512 with a 64-byte default output and an explicit HMAC-work budget.
- `Numeric`: `UInt256`, `UInt512`, and budgeted `BigUnsignedInteger` facade wrappers.

The Base32 APIs use the Bech32 alphabet and stay intentionally low-level. Use nonthrowing `encodeBase32(bytes:)` with `decodeBase32Bytes(_:maximumDecodedByteCount:)` for byte-mode radix conversion, and `Encoding.FiveBitValues` with nonthrowing `encodeBase32(values:)` and `decodeBase32Values(_:)` for five-bit symbol mode. Base58 decoding offers `decodeBase58IfValid(_:maximumDecodedByteCount:)` for optional failure and `decodeBase58Validating(_:maximumDecodedByteCount:)` for an explicit error.

See [docs/public-api.md](docs/public-api.md) for the typed public facade shape.

## Boundaries

- In scope: facade-first cryptography for BCH operations, genuine BIP340 signatures over typed 32-byte digests, bounded RFC 9474 RSA blind signatures, NIP-44 v2 encrypted payloads, AES-256-GCM authenticated encryption, secp256k1 keys, hashing, bounded secure randomness, encoding, key derivation, and numeric primitives.
- Out of scope: wallet or app-domain orchestration, address management, RPA scan policy, mailbox routing, Nostr event kinds or codecs, network or protocol/runtime responsibilities, non-Swift expansion, or reliance on internal implementation details as public API. Higher-level packages own their protocol construction; Opal Crypto only supplies the cryptographic computation primitives they need.

See [docs/engineering-principles.md](docs/engineering-principles.md) for the Swift-first implementation boundary, Apple-native acceleration policy, and benchmark-backed performance expectations. See [docs/architecture-complexity-audit.md](docs/architecture-complexity-audit.md) for the current ownership map and bounded cleanup backlog, [docs/performance-roadmap.md](docs/performance-roadmap.md) for the CPU-to-Metal optimization stages, and [docs/metal-readiness.md](docs/metal-readiness.md) for the current Metal qualification boundary.

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

## Further Context

See [docs/context.md](docs/context.md) for package role, repo boundaries, and integration expectations.
