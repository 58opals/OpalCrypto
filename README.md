# OpalCrypto

A Swift package that provides practical cryptography primitives through a focused public boundary API.

## Features

`OpalCryptoBoundaryModel` groups stable public APIs into feature namespaces:

- `SignatureModel`: derive secp256k1 public keys, sign, and verify using ECDSA or Schnorr formats.
- `HashingModel`: SHA-256 family helpers, SHA-160 helper, and HMAC-SHA512.
- `EncodingModel`: Base58 encode/decode, Base32 encode/decode, and polynomial checksum.
- `KeyDerivationModel`: PBKDF2 key derivation.
- `NumericModel`: large unsigned integer aliases for arithmetic-oriented workflows.

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

let publicKeyData = try OpalCryptoBoundaryModel.SignatureModel.derivePublicKey(
    fromPrivateKeyData: privateKeyData
)

let signatureData = try OpalCryptoBoundaryModel.SignatureModel.sign(
    messageData: messageData,
    privateKeyData: privateKeyData,
    format: .ecdsa(.distinguishedEncodingRules)
)

let isValid = try OpalCryptoBoundaryModel.SignatureModel.verify(
    signatureData: signatureData,
    messageData: messageData,
    publicKeyData: publicKeyData,
    format: .ecdsa(.distinguishedEncodingRules)
)
```

For Schnorr signatures, use `format: .schnorr` and optionally set
`nonceGenerationPolicy: .bitcoinImprovementProposalSchnorrDeterministic`.

### Example B: Hash, Base58 Roundtrip, and PBKDF2

```swift
import Foundation
import OpalCrypto

let payloadData = Data("opal-api-boundary".utf8)

let sha256 = OpalCryptoBoundaryModel.HashingModel.makeSecureHashAlgorithm256(payloadData)
let doubleSha256 = OpalCryptoBoundaryModel.HashingModel.makeSecureHash256(payloadData)
let hash160 = OpalCryptoBoundaryModel.HashingModel.makeSecureHash160(payloadData)

let base58Text = OpalCryptoBoundaryModel.EncodingModel.encodeBase58(payloadData)
let decodedPayload = OpalCryptoBoundaryModel.EncodingModel.decodeBase58(base58Text)

let derivedKey = try OpalCryptoBoundaryModel.KeyDerivationModel.derivePasswordBasedKeyDerivationFunction2Key(
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
