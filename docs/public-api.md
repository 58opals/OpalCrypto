# OpalCrypto Public API

`OpalCrypto` exposes one public facade with nested capability namespaces:

- `OpalCrypto.Signature`
- `OpalCrypto.Secp256k1`
- `OpalCrypto.Key`
- `OpalCrypto.Hashing`
- `OpalCrypto.Encoding`
- `OpalCrypto.KeyDerivation`
- `OpalCrypto.Pedersen`
- `OpalCrypto.BlindSignature`
- `OpalCrypto.Communication`

The split files in `Sources/OpalCrypto/PublicAPI` are the source of truth. This page is a compact integration guide for the breaking typed-byte facade.

## Byte Value Rule

Free-form payloads remain `Data`: messages, passwords, arbitrary encoding bytes, and hash input bytes.

Constrained cryptographic or protocol-shaped byte strings use facade-owned value types with validating initializers and `rawRepresentation` accessors:

- `Secp256k1.PrivateKey`, `Secp256k1.PublicKey`, `Secp256k1.Scalar`, `Secp256k1.SharedSecret`
- `Signature.Digest`, `Signature.ECDSA`, `Signature.Schnorr`, `Signature.VerificationKey`
- `Communication.Ciphertext`, `Communication.SymmetricKey`
- `Pedersen.Nonce`, `Pedersen.CommitmentPoint`, `Pedersen.Commitment`
- `Key.Seed`, `Key.WIF`, `Key.ExtendedPrivate`, `Key.ExtendedPublic`
- `KeyDerivation.Salt`, `KeyDerivation.DerivedKey`
- `Encoding.FiveBitValues`

## Common Calls

```swift
import Foundation
import OpalCrypto

let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

let message = Data("opal-signature-message".utf8)
let digest = try OpalCrypto.Signature.Digest(
    rawRepresentation: OpalCrypto.Hashing.sha256(message)
)
let ecdsa = try OpalCrypto.Signature.ECDSA.sign(
    digest: digest,
    privateKey: privateKey,
    format: .der
)
let ecdsaIsValid = try ecdsa.verify(digest: digest, publicKey: publicKey)

let schnorr = try OpalCrypto.Signature.Schnorr.sign(
    digest: digest,
    privateKey: privateKey
)
let schnorrIsValid = try schnorr.verify(digest: digest, publicKey: publicKey)
```

## Encoding

Base32 byte mode and Bech32-style five-bit value mode are separate APIs:

```swift
let byteText = try OpalCrypto.Encoding.encodeBase32Bytes(Data([0x00, 0x10]))
let bytes = try OpalCrypto.Encoding.decodeBase32Bytes(byteText)

let values = try OpalCrypto.Encoding.FiveBitValues(rawRepresentation: Data([0, 1, 31]))
let valueText = try OpalCrypto.Encoding.encodeBase32Values(values)
let decodedValues = try OpalCrypto.Encoding.decodeBase32Values(valueText)
let checksum = OpalCrypto.Encoding.computePolymodChecksum(values)
```

## Error Boundary

Public errors live under the facade namespaces. Typed value construction reports shape errors before an operation reaches the internal crypto model, and operation errors are mapped back to facade-owned error enums. Internal model names are not part of the public contract.
