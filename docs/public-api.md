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

Secret-bearing signing workflows should prefer `Secp256k1.SigningKey`. It is an opaque signing capability that can be imported from raw private-key bytes, `Secp256k1.PrivateKey`, `Key.WIF`, or `Key.ExtendedPrivate`, but it does not expose raw private-key bytes or serialization APIs.

## Common Calls

```swift
import Foundation
import OpalCrypto

let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
let signingKey = try privateKey.makeSigningKey()
let publicKey = signingKey.publicKey

let message = Data("opal-signature-message".utf8)
let digest = try OpalCrypto.Signature.Digest(
    rawRepresentation: OpalCrypto.Hashing.sha256(message)
)
let ecdsa = try signingKey.signECDSA(
    digest: digest,
    format: .der
)
let ecdsaIsValid = try ecdsa.verify(digest: digest, publicKey: publicKey)

let schnorr = try signingKey.signSchnorr(digest: digest)
let schnorrIsValid = try schnorr.verify(digest: digest, publicKey: publicKey)
```

## Secret Export Boundaries

`Secp256k1.PrivateKey.rawRepresentation`, `Key.WIF.privateKey`, `Key.WIF.serialize()`, `Key.ExtendedPrivate.privateKey`, and `Key.ExtendedPrivate.serialize()` remain source-compatible legacy and import/export boundaries. Use them only when raw private-key bytes, WIF text, or xprv text must cross an explicit storage, backup, migration, or interoperability boundary. For signing, retain `Secp256k1.SigningKey` and call its signing methods instead of repeatedly reading raw private-key bytes.

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
