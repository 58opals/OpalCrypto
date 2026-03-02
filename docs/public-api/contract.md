# OpalCrypto Public API Contract

## Contract Mode

- Hard cut migration: no deprecation window.
- Only `OpalCryptoFacade` is public.
- `public`/`open` declarations are allowed only under `Sources/OpalCrypto/PublicAPI/`.

## Stable Namespace

`OpalCryptoFacade`

### Signature

- `OpalCryptoFacade.Signature.Format`
  - `.ecdsa(.raw)`
  - `.ecdsa(.der)`
  - `.schnorr`
- `OpalCryptoFacade.Signature.NoncePolicy`
  - `.requestForComments6979`
  - `.bitcoinImprovementProposalSchnorrDeterministic`
  - `.systemRandom`
- `OpalCryptoFacade.Signature.Error`
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

- `OpalCryptoFacade.Numeric.UInt256`
- `OpalCryptoFacade.Numeric.UInt512`
- `OpalCryptoFacade.Numeric.BigUnsignedInteger`
- `OpalCryptoFacade.Numeric.Error`

## Prohibited Public Exposure

No public API may expose these internal implementation families:

- `EllipticCurveDigitalSignatureAlgorithmModel`
- `SchnorrSignatureModel`
- `StandardsForEfficientCryptography256k1CurveModel`
- `NonceGenerationPolicy`
- `Unsigned256BitIntegerModel`
- `Unsigned512BitIntegerModel`
- `LargeUnsignedIntegerArithmeticModel`
