# OpalCrypto Public API Contract

## Contract Mode

- Hard cut migration: no deprecation window.
- Only `OpalCryptoBoundaryModel` is public.
- `public`/`open` declarations are allowed only under `Sources/OpalCrypto/PublicAPI/`.

## Stable Namespace

`OpalCryptoBoundaryModel`

### Signature

- `OpalCryptoBoundaryModel.Signature.Format`
  - `.ecdsa(.raw)`
  - `.ecdsa(.der)`
  - `.schnorr`
- `OpalCryptoBoundaryModel.Signature.NoncePolicy`
  - `.requestForComments6979`
  - `.bitcoinImprovementProposalSchnorrDeterministic`
  - `.systemRandom`
- `OpalCryptoBoundaryModel.Signature.Error`
- `derivePublicKey(fromPrivateKeyData:)`
- `sign(messageData:privateKeyData:format:noncePolicy:)`
- `verify(signatureData:messageData:publicKeyData:format:)`

### Hashing

- `makeSecureHashAlgorithm256(_:)`
- `makeSecureHash256(_:)`
- `makeSecureHash160(_:)`
- `makeHashBasedMessageAuthenticationCodeSecureHashAlgorithm512(data:key:)`

### Encoding

- `encodeBase58(_:)`
- `decodeBase58(_:)`
- `encodeBase32(_:interpretedAsFiveBitValues:)`
- `decodeBase32(_:interpretedAsFiveBitValues:)`
- `computePolynomialModuloChecksum(_:)`

### Key Derivation

- `derivePasswordBasedKeyDerivationFunction2Key(passwordData:saltData:iterationCount:derivedKeyLength:)`

### Numeric

- `OpalCryptoBoundaryModel.Numeric.UInt256`
- `OpalCryptoBoundaryModel.Numeric.UInt512`
- `OpalCryptoBoundaryModel.Numeric.BigUnsignedInteger`
- `OpalCryptoBoundaryModel.Numeric.Error`

## Prohibited Public Exposure

No public API may expose these internal implementation families:

- `EllipticCurveDigitalSignatureAlgorithmModel`
- `SchnorrSignatureModel`
- `StandardsForEfficientCryptography256k1CurveModel`
- `NonceGenerationPolicy`
- `Unsigned256BitIntegerModel`
- `Unsigned512BitIntegerModel`
- `LargeUnsignedIntegerArithmeticModel`
