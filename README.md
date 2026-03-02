# OpalCrypto

A Swift package that exposes cryptography through a strict facade-first public API.

## Features

`OpalCryptoFacade` is the only public namespace:

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

let publicKeyData = try OpalCryptoFacade.Signature.derivePublicKey(
    fromPrivateKeyData: privateKeyData
)

let signatureData = try OpalCryptoFacade.Signature.sign(
    messageData: messageData,
    privateKeyData: privateKeyData,
    format: .ecdsa(.der),
    noncePolicy: .requestForComments6979
)

let isValid = try OpalCryptoFacade.Signature.verify(
    signatureData: signatureData,
    messageData: messageData,
    publicKeyData: publicKeyData,
    format: .ecdsa(.der)
)
```

For Schnorr signatures, use `format: .schnorr` and pass 32-byte digest data.

### Example B: Hash, Base58 Roundtrip, and PBKDF2

```swift
import Foundation
import OpalCrypto

let payloadData = Data("opal-api-facade".utf8)

let sha256 = OpalCryptoFacade.Hashing.makeSecureHashAlgorithm256(payloadData)
let doubleSha256 = OpalCryptoFacade.Hashing.makeSecureHash256(payloadData)
let hash160 = OpalCryptoFacade.Hashing.makeSecureHash160(payloadData)

let base58Text = OpalCryptoFacade.Encoding.encodeBase58(payloadData)
let decodedPayload = OpalCryptoFacade.Encoding.decodeBase58(base58Text)

let derivedKey = try OpalCryptoFacade.KeyDerivation.derivePasswordBasedKeyDerivationFunction2Key(
    passwordData: Data("password".utf8),
    saltData: Data("salt".utf8),
    iterationCount: 4096,
    derivedKeyLength: 32
)
```

## Testing

Run the package test suite:

```bash
swift test
```
