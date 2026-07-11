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

## Schnorr Verification Batches

`OpalCrypto.Signature.Schnorr.VerificationBatch` verifies independent Bitcoin Cash Schnorr records while preserving input order. It returns one `Bool` per record; it is not probabilistic aggregate-signature verification. A mixed batch of valid and invalid signatures completes successfully, with each Boolean describing its corresponding record.

Use one prepared verification key when every record shares a public key:

```swift
let verificationKey = OpalCrypto.Signature.VerificationKey(publicKey: publicKey)
let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
    signatures: signatures,
    digests: digests,
    verificationKey: verificationKey
)

let results = try await batch.verify()
```

Use the varying-key initializer when each record has its own secp256k1 public key:

```swift
let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
    signatures: signatures,
    digests: digests,
    publicKeys: publicKeys
)

let results = try await batch.verify(using: .cpu)
```

`count` and `isEmpty` describe the immutable batch. Construction rejects mismatched signature, digest, or public-key counts before execution. An empty batch returns `[]` for every policy after checking task cancellation.

The execution policies are:

- `.automatic`: selects the qualified backend for the workload and environment. It uses Swift CPU execution below the qualified crossover, on unqualified devices and platforms, in Low Power Mode, and under serious or critical thermal pressure. A non-cancellation Metal failure discards all GPU output and recomputes the entire batch on the CPU.
- `.cpu`: requires ordered, optimized multicore Swift execution.
- `.metal`: requires a qualified Metal backend, even below the automatic crossover, and never falls back to the CPU. It throws `executionUnavailable(policy:)` when Metal is not qualified or available and `executionFailed(policy:)` when execution cannot complete.

Cancellation propagates as `CancellationError` and never triggers fallback. Metal processes only public signatures, digests, and public keys; signing, nonces, private scalars, ECDH, and reusable payment address scan keys are outside this API.

The initial production qualification envelope is macOS on the exact `Apple M1 Max` device name with Apple GPU family 7. Warm automatic selection starts at 4,096 records; a cold path that has not paid pipeline initialization and self-test starts at 8,192. That profile passed the five-process production-API qualification recorded in [metal-readiness.md](metal-readiness.md). Other device and platform profiles remain on CPU under `.automatic`, and explicit `.metal` is unavailable unless that profile is certified.

Batch diagnostics are aggregate and privacy-safe: policy, selected backend, cached-key or varying-key shape, counts, stage durations, and stable low-cardinality Metal failure reasons. They never record signatures, digests, public keys, device names, driver strings, record indices, or per-record results.

## Batch Shared Secrets

Use `OpalCrypto.Secp256k1.deriveSharedSecrets(privateKey:publicKeys:)` when a higher-level package needs ordered secp256k1 ECDH-style computation across many candidate public keys. Each `SharedSecret` matches the single-key `deriveSharedSecret(privateKey:publicKey:)` representation: SHA-256 of the compressed shared EC point.

This is intentionally not an RPA address-management API. Opal Base owns reusable payment address parsing, scan policy, output matching, address derivation, persistence, and indexer integration; Opal Crypto supplies the cryptographic batch primitive.

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
