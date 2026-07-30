// OpalCrypto.Key~ChildDerivation.swift

extension OpalCrypto.Key {
    /// Derives one BIP-32 non-hardened child from an explicit public key and
    /// chain code.
    ///
    /// The result is a validated secp256k1 public key. This focused operation
    /// does not fabricate extended-key depth, parent fingerprint, or child
    /// metadata.
    public static func deriveNonHardenedChildPublicKey(
        from parentPublicKey: OpalCrypto.Secp256k1.PublicKey,
        chainCode: ChainCode,
        at index: UInt32
    ) throws -> OpalCrypto.Secp256k1.PublicKey {
        do {
            let child = try ExtendedKeyDerivationModel
                .deriveNonHardenedPublicChild(
                    from: parentPublicKey.parsedPublicKeyModel,
                    chainCode: chainCode.rawRepresentation,
                    index: index
                )
            return OpalCrypto.Secp256k1.PublicKey(
                parsedPublicKeyModel: child
            )
        } catch let error as ExtendedKeyDerivationModel.Error {
            throw mapChildDerivationError(error, index: index)
        }
    }

    /// Derives one BIP-32 non-hardened child from an opaque signing key and
    /// explicit chain code.
    ///
    /// The result remains an opaque signing capability and never exports raw
    /// child private-key bytes. The child public point is derived through the
    /// equivalent public tweak, so this operation does not perform generator
    /// multiplication with the derived private scalar.
    public static func deriveNonHardenedChildSigningKey(
        from parentSigningKey: OpalCrypto.Secp256k1.SigningKey,
        chainCode: ChainCode,
        at index: UInt32
    ) throws -> OpalCrypto.Secp256k1.SigningKey {
        do {
            let child = try ExtendedKeyDerivationModel
                .deriveNonHardenedPrivateChild(
                    from: parentSigningKey.parsedPrivateKeyModel,
                    chainCode: chainCode.rawRepresentation,
                    index: index
                )
            return OpalCrypto.Secp256k1.SigningKey(
                parsedPrivateKeyModel: child
            )
        } catch let error as ExtendedKeyDerivationModel.Error {
            throw mapChildDerivationError(error, index: index)
        }
    }

    private static func mapChildDerivationError(
        _ error: ExtendedKeyDerivationModel.Error,
        index: UInt32
    ) -> ChildDerivationError {
        switch error {
        case .hardenedDerivationRequiresPrivateKey:
            return .hardenedIndex(index)
        case .invalidSeed,
             .invalidKeyKind,
             .depthOverflow,
             .invalidDerivedKey:
            return .invalidDerivedKey
        }
    }
}
