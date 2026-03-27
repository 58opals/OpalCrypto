# Opal Crypto

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

The current public facade surface is published from the `develop` branch.

```swift
dependencies: [
    .package(url: "https://github.com/58opals/OpalCrypto.git", branch: "develop")
]
```

Then add `"OpalCrypto"` to the target dependency list where you need it.

## Quick Start

```swift
import Foundation
import OpalCrypto

var privateKey = Data(repeating: 0x00, count: 32)
privateKey[31] = 0x01
let message = Data("opal-ecdsa-message".utf8)

let publicKey = try OpalCrypto.Signature.derivePublicKey(
    fromPrivateKey: privateKey
)
let signature = try OpalCrypto.Signature.sign(
    message: message,
    privateKey: privateKey,
    format: .ecdsa(.der)
)
let isValid = try OpalCrypto.Signature.verify(
    signature: signature,
    message: message,
    publicKey: publicKey,
    format: .ecdsa(.der)
)
```

For Schnorr signatures, use `format: .schnorr` and pass a 32-byte digest as the message input.

## Key Capabilities

- `Signature`: secp256k1 public-key derivation plus ECDSA and Schnorr signing and verification with facade-owned formats and nonce policies.
- `Key`: WIF, BIP-39 mnemonics, and extended private/public keys.
- `Hashing`: SHA-256, Hash256, Hash160, and HMAC-SHA512 helpers.
- `Encoding`: Base58 plus Bech32-style Base32 and polymod checksum primitives.
- `KeyDerivation`: PBKDF2 key derivation.
- `Numeric`: `UInt256`, `UInt512`, and `BigUnsignedInteger` facade wrappers.

The Base32 APIs use the Bech32 alphabet and stay intentionally low-level; `interpretedAsFiveBitValues` switches between five-bit symbol input and byte-mode radix conversion.

## Boundaries

- In scope: facade-first BCH cryptography for keys, secp256k1, hashing, encoding, key derivation, and numeric primitives.
- Out of scope: wallet or app-domain orchestration, network or protocol/runtime responsibilities, non-BCH features, non-Swift expansion, or reliance on internal implementation details as public API.

## Testing

```bash
swift test
```

## Further Context

See [docs/context.md](docs/context.md) for package role, repo boundaries, and integration expectations.
