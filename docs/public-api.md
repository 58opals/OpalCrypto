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
- `OpalCrypto.Numeric`
- `OpalCrypto.SecureRandom`
- `OpalCrypto.Nostr.NIP44`

The split files in `Sources/OpalCrypto/PublicAPI` are the source of truth. This page is a compact integration guide for the breaking typed-byte facade.

## Byte Value Rule

Free-form payloads remain `Data`: messages, passwords, arbitrary encoding bytes, and hash input bytes.

Constrained cryptographic or protocol-shaped byte strings use facade-owned value types with validating initializers and `rawRepresentation` accessors:

- `Secp256k1.PrivateKey`, `Secp256k1.PublicKey`, `Secp256k1.Scalar`, `Secp256k1.SharedSecret`, `Secp256k1.SharedPointXCoordinate`
- `Signature.Digest`, `Signature.ECDSA`, `Signature.Schnorr`, `Signature.VerificationKey`, `Signature.BIP340`, `Signature.BIP340.VerificationKey`, `Signature.BIP340.AuxiliaryRandomness`
- `Communication.Ciphertext`, `Communication.SymmetricKey`
- `Pedersen.Nonce`, `Pedersen.CommitmentPoint`, `Pedersen.Commitment`
- `Key.Seed`, `Key.WIF`, `Key.ChainCode`, `Key.Fingerprint`, `Key.ExtendedPrivate`, `Key.ExtendedPublic`
- `KeyDerivation.Salt`, `KeyDerivation.DerivedKey`
- `Encoding.FiveBitValues`
- `Numeric.UInt256`, `Numeric.UInt512`, `Numeric.BigUnsignedInteger`
- `Nostr.NIP44.ConversationKey`, `Nostr.NIP44.Nonce`, `Nostr.NIP44.Payload`

`Secp256k1.PublicKey` and `Signature.VerificationKey` accept compressed or uncompressed SEC1 input, while `rawRepresentation` is always the canonical compressed 33-byte form. `Pedersen.CommitmentPoint` accepts either SEC1 form, but its `rawRepresentation` is the canonical uncompressed 65-byte form; use `compressedRepresentation` when a compressed point is required.

Secret-bearing signing workflows should prefer `Secp256k1.SigningKey`. It is an opaque signing capability that can be imported from raw private-key bytes, `Secp256k1.PrivateKey`, `Key.WIF`, or `Key.ExtendedPrivate`, but it does not expose raw private-key bytes or serialization APIs.

Use `SigningKey.signECDSASHA256(message:)` when the operation should hash arbitrary message bytes once with SHA-256. Use `SigningKey.signECDSA(digest:)` for an already computed 32-byte digest; the source-compatible `signECDSA(message:)` operation also hashes once with SHA-256.

Use `SigningKey.signBIP340(digest:auxiliaryRandomness:)` for genuine BIP340. The auxiliary randomness argument is a required, validated 32-byte value with redacted string descriptions; there is no default that silently chooses signing-time entropy policy.

## Common Calls

```swift
import Foundation
import OpalCrypto

let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
let signingKey = privateKey.makeSigningKey()
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

When the message itself is the input, the explicitly named ECDSA operations hash it once with SHA-256:

```swift
let ecdsa = try OpalCrypto.Signature.ECDSA.signSHA256(
    message: message,
    privateKey: privateKey
)
let ecdsaIsValid = try ecdsa.verifySHA256(message: message, publicKey: publicKey)
```

Use the `digest:` overloads for an already computed 32-byte digest; they do not hash it again.

Schnorr signing defaults to `.bchDeterministic`, the Bitcoin Cash RFC 6979 variant with `Schnorr+SHA256` additional data. The deprecated `.bip340Deterministic` case preserves its historical `SHA256(privateKey || digest)` behavior for source compatibility; despite its legacy name, it does not implement BIP 340.

## BIP340 Signatures

`Signature.BIP340` is separate from the Bitcoin Cash `Signature.Schnorr` type. It implements BIP340 tagged hashes, 32-byte x-only verification keys with implicit even Y, and 64-byte `r || s` signatures. OpalCrypto intentionally accepts the existing 32-byte `Signature.Digest` as BIP340's message `m`; callers own prehashing and application-level domain separation.

```swift
let auxiliaryBytes = try OpalCrypto.SecureRandom.makeBytes(count: 32)
let auxiliaryRandomness = try OpalCrypto.Signature.BIP340.AuxiliaryRandomness(
    rawRepresentation: auxiliaryBytes
)
let bip340Signature = try signingKey.signBIP340(
    digest: digest,
    auxiliaryRandomness: auxiliaryRandomness
)
let bip340IsValid = bip340Signature.verify(
    digest: digest,
    verificationKey: signingKey.bip340VerificationKey
)
```

The signing path uses fixed-schedule hardened scalar multiplication and scalar arithmetic, verifies the completed signature before returning it, and never exports the private scalar from `Secp256k1.SigningKey`.

## NIP-44 Version 2

`Nostr.NIP44` implements the version 2 encrypted-payload construction: the unhashed secp256k1 shared-point x-coordinate, HKDF with SHA-256, NIP-44 padding, RFC 8439 ChaCha20 with counter zero, HMAC-SHA256 authentication, and canonical padded base64. It does not define Nostr event kinds, relay behavior, fixed outer protocol sizes, anonymous transport, or a messaging protocol.

```swift
let recipientKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
    .makeSigningKey()
let conversationKey = OpalCrypto.Nostr.NIP44.deriveConversationKey(
    signingKey: signingKey,
    publicKey: recipientKey.bip340VerificationKey
)
let payload = try OpalCrypto.Nostr.NIP44.encrypt(
    "encrypted payload",
    conversationKey: conversationKey,
    maximumPlaintextByteCount: 4_096
)
```

Every encryption call generates a 32-byte nonce unless the explicit-nonce conformance entry point is used. Callers must never reuse an explicit nonce with the same conversation key. Imported payloads and decrypt operations require caller-owned encoded-payload and plaintext limits so untrusted base64 cannot cause an unbounded allocation. Before decrypting, callers must validate the identifier, public key, and BIP340 signature of the NIP-01 event containing the payload; NIP-44 alone does not authenticate which peer sent it. `ConversationKey` and `Nonce` descriptions are redacted.

## Secure Random Bytes

`OpalCrypto.SecureRandom.makeBytes(count:)` uses the operating system secure random generator and accepts `1...1024` bytes. That range is an OpalCrypto allocation-safety boundary, not a Mosaic or BIP340 protocol constant. Protocol-shaped outputs should immediately cross into their validating facade value, as shown for BIP340's exactly 32-byte `AuxiliaryRandomness` above.

## Pedersen Commitments

Create `Pedersen.Setup` with `try OpalCrypto.Pedersen.Setup()`. The setup uses the fixed CashFusion independent base point, whose compressed encoding is `0x02 || UTF-8("CashFusion gives us fungibility.")`; callers cannot select a different point. The deprecated `init(alternateBasePoint:)` bridge remains source-compatible only when passed that same point and rejects every other point with `Pedersen.Error.insecureAlternateBasePoint`.

## Blind Signatures

`BlindSignature.Signer` owns exactly one nonce. Call `signOnce(privateKey:requestScalar:)` to make nonce consumption explicit. Every alias of the actor shares that state, and any signing attempt after the first successful response throws `BlindSignature.Error.nonceAlreadyUsed`.

`BlindSignature.Request.finalize(responseScalar:)` verifies the completed signature. When verification is deliberately handled elsewhere, call the explicitly named `finalizeWithoutVerification(responseScalar:)`; structural signature validation still applies.

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

## Shared-Point Profiles

Use `OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(signingKey:publicKey:)` when a consuming protocol needs the exact 32-byte affine x-coordinate of the shared secp256k1 point while retaining an opaque signing capability. A `privateKey:publicKey:` overload is available at an explicit raw-key boundary. Neither operation adds a prefix or hashes the coordinate. The consuming profile owns that domain construction.

`SharedPointXCoordinate` is secret-bearing. Its `description` and `debugDescription` are redacted; access `rawRepresentation` only at the explicit profile boundary that consumes the coordinate.

This operation has a dedicated fixed 256-round scalar-multiplication path. Every round performs one complete point doubling and addition and selects by mask; it does not use the variable-time wNAF path behind the source-compatible `deriveSharedSecret` and `deriveSharedSecrets` operations. The legacy operations continue to return SHA-256 of the compressed shared EC point, so their output is not interchangeable with an x-coordinate profile.

## Explicit-Chain-Code Child Derivation

Use `OpalCrypto.Key.deriveNonHardenedChildPublicKey(from:chainCode:at:)` to derive a BIP-32 child public key directly from a validated secp256k1 public key and 32-byte `Key.ChainCode`. Use `deriveNonHardenedChildSigningKey(from:chainCode:at:)` for the symmetric private operation. The latter accepts and returns opaque `Secp256k1.SigningKey` capabilities; it does not export child private-key bytes.

These focused operations derive exactly one non-hardened child. They do not fabricate extended-key depth, parent fingerprint, or child metadata. An index with the hardened bit set throws `Key.ChildDerivationError.hardenedIndex(_:)`. Both paths use fixed-schedule point multiplication for chain-code-derived tweak material.

## Secret Export Boundaries

`Secp256k1.PrivateKey.rawRepresentation`, `Key.WIF.privateKey`, `Key.WIF.serialize()`, `Key.ExtendedPrivate.privateKey`, and `Key.ExtendedPrivate.serialize()` remain source-compatible legacy and import/export boundaries. Use them only when raw private-key bytes, WIF text, or xprv text must cross an explicit storage, backup, migration, or interoperability boundary. For signing, retain `Secp256k1.SigningKey` and call its signing methods instead of repeatedly reading raw private-key bytes.

Conversions from validated `PrivateKey` or `WIF` values to `SigningKey` are nonthrowing. WIF serialization is also nonthrowing because a `WIF` already contains a validated private key; parsing serialized WIF text remains a throwing import boundary.

## Mnemonic Word Lists

`Key.Mnemonic.WordList` is a `RandomAccessCollection` of normalized words. Use collection indices and `firstIndex(of:)`; the source-compatible `words`, `contains(_:)`, and `index(of:)` conveniences remain available.

Mnemonic phrase import rejects more than 24 words without fabricating an exact word count. It also bounds the raw UTF-8 phrase to 8,192 bytes and each raw word to 256 bytes before compatibility normalization, so malformed input cannot amplify normalization work without limit.

## Communication Padding

`Communication.encrypt(message:recipientPublicKey:paddedPlaintextLength:maximumCiphertextByteCount:)` prefixes the message with its four-byte length. With no explicit padding length, the plaintext expands to the smallest multiple of 16 that contains the prefix and message. An explicit `paddedPlaintextLength` must be at least `message.count + 4` and a multiple of 16; otherwise encryption throws a facade-owned padding error.

Every communication entry point requires the largest serialized ciphertext the caller is willing to process. Encryption checks the complete envelope size before key generation or allocation. `Communication.Ciphertext.init(rawRepresentation:maximumCiphertextByteCount:)` checks imported data before copying it, and both `decrypt` overloads enforce the current operation's budget before cryptographic work.

## Encoding

Base32 byte mode and Bech32-style five-bit value mode are separate APIs:

```swift
let byteText = OpalCrypto.Encoding.encodeBase32(bytes: Data([0x00, 0x10]))
let bytes = try OpalCrypto.Encoding.decodeBase32Bytes(
    byteText,
    maximumDecodedByteCount: 2
)

let values = try OpalCrypto.Encoding.FiveBitValues(rawRepresentation: Data([0, 1, 31]))
let valueText = OpalCrypto.Encoding.encodeBase32(values: values)
let decodedValues = try OpalCrypto.Encoding.decodeBase32Values(valueText)
let checksum = OpalCrypto.Encoding.computePolymodChecksum(values)
```

Generic Base58 and byte-mode Base32 decoding require an explicit maximum decoded byte count and stop when the result would cross it. Base58 decoding has explicit failure shapes: `decodeBase58IfValid(_:maximumDecodedByteCount:)` returns `nil`, while `decodeBase58Validating(_:maximumDecodedByteCount:)` distinguishes invalid text, an invalid limit, and a result that exceeds the limit. Fixed-format WIF and extended-key imports apply their exact protocol bounds internally and report `payloadLengthExceedsMaximum(maximum:)` when conversion stops before an exact oversized length is known.

## Key Derivation

`KeyDerivation.derivePBKDF2SHA512Key(password:salt:iterationCount:derivedKeyLength:maximumWorkUnitCount:)` uses PBKDF2 with HMAC-SHA-512. Omitting `derivedKeyLength` produces 64 bytes. One work unit is one HMAC evaluation, so the required work is the number of 64-byte output blocks multiplied by `iterationCount`. The operation validates that multiplication and the caller's budget before retaining the password or allocating the result. Salt values must be nonempty, iteration counts must be positive, and invalid lengths, work overflow, or insufficient budgets throw facade-owned `KeyDerivation.Error` values.

## Arbitrary-Precision Shifts

`Numeric.BigUnsignedInteger.shiftedLeft(byBytes:maximumResultByteCount:)` requires the caller to bound the nonzero result allocation. It reports a budget overrun as `Numeric.BigUnsignedInteger.LeftShiftError.exceedsMaximumResultByteCount(requiredByteCount:maximumResultByteCount:)` and an arithmetic or in-memory representation overflow as `exceedsRepresentableSize(byteCount:)`. Shifting zero returns zero without allocation.

`Numeric.BigUnsignedInteger.init(bigEndianRepresentation:)` accepts a variable-width unsigned big-endian value, normalizes leading zeroes, and treats empty data as zero. Its `bigEndianRepresentation` is minimal and represents zero as empty data. `Numeric.UInt256.init(bigEndianRepresentation:)` instead requires exactly 32 bytes, and its representation always remains fixed-width.

## Error Boundary

Public errors live under the facade namespaces. Typed value construction reports shape errors before an operation reaches the internal crypto model, and operation errors are mapped back to facade-owned error enums. Internal model names are not part of the public contract.
