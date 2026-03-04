# OpalCrypto

A Swift package that exposes cryptography through a strict facade-first public API.

## Features

`OpalCrypto` is the only public namespace:

- `Signature`: derive secp256k1 public keys, sign, and verify with facade-owned formats and nonce policies.
- `Hashing`: SHA-256 family helpers, SHA-160 helper, and HMAC-SHA512.
- `Encoding`: Base58 encode/decode, Base32 encode/decode, and polynomial checksum.
- `KeyDerivation`: PBKDF2 key derivation.
- `Numeric`: facade wrappers `UInt256`, `UInt512`, and `BigUnsignedInteger`.

## Requirements

- Swift tools version: `6.2`
- Platforms:
  - `macOS 26`
  - `iOS 26`
  - `watchOS 26`
  - `tvOS 26`
  - `visionOS 26`

## Installation (SwiftPM)

Add OpalCrypto to your package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/58opals/OpalCrypto.git", branch: "main")
]
```

Then add `"OpalCrypto"` to the target dependency list where you need it.

## Quickstart

### Example A: Derive Public Key, Sign, and Verify

```swift
import Foundation
import OpalCrypto

var privateKeyData = Data(repeating: 0x00, count: 32)
privateKeyData[31] = 0x01
let messageData = Data("opal-ecdsa-message".utf8)

let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
    fromPrivateKey: privateKeyData
)

let signatureData = try OpalCrypto.Signature.sign(
    message: messageData,
    privateKey: privateKeyData,
    format: .ecdsa(.der),
    nonce: .rfc6979
)

let isValid = try OpalCrypto.Signature.verify(
    signature: signatureData,
    message: messageData,
    publicKey: publicKeyData,
    format: .ecdsa(.der)
)
```

For Schnorr signatures, use `format: .schnorr` and pass 32-byte digest data.

### Example B: Hash, Base58 Roundtrip, and PBKDF2

```swift
import Foundation
import OpalCrypto

let payloadData = Data("opal-api-facade".utf8)

let sha256 = OpalCrypto.Hashing.computeSHA256(payloadData)
let doubleSha256 = OpalCrypto.Hashing.computeHash256(payloadData)
let hash160 = OpalCrypto.Hashing.computeHash160(payloadData)

let base58Text = OpalCrypto.Encoding.encodeBase58(payloadData)
let decodedPayload = OpalCrypto.Encoding.decodeBase58(base58Text)

let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
    password: Data("password".utf8),
    salt: Data("salt".utf8),
    iterationCount: 4096,
    derivedKeyLength: 32
)
```

## Testing

Run the package test suite:

```bash
swift test
```
