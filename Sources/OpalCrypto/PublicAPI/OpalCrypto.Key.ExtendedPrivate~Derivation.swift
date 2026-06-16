// OpalCrypto.Key.ExtendedPrivate~Derivation.swift

extension OpalCrypto.Key.ExtendedPrivate {
    /// Derives a child extended private key at the given BIP-32 indices.
    ///
    /// The returned key is secret-bearing. Hardened and non-hardened private derivation are both allowed by this API.
    public func derived(indices: [UInt32]) throws -> OpalCrypto.Key.ExtendedPrivate {
        var currentPayload = payload
        var currentParsedPrivateKeyModel = parsedPrivateKeyModel
        for index in indices {
            do {
                let childMaterial = try ExtendedKeyDerivationModel
                    .derivePrivateChildMaterial(
                    from: currentPayload,
                    parsedPrivateKeyModel: currentParsedPrivateKeyModel,
                    index: index
                )
                currentPayload = childMaterial.payload
                currentParsedPrivateKeyModel = childMaterial.parsedPrivateKeyModel
            } catch let error as ExtendedKeyDerivationModel.Error {
                throw Self.mapDerivationError(error)
            }
        }
        return OpalCrypto.Key.ExtendedPrivate(
            payload: currentPayload,
            parsedPrivateKeyModel: currentParsedPrivateKeyModel
        )
    }

    private static func mapDerivationError(_ error: ExtendedKeyDerivationModel.Error) -> OpalCrypto.Key.ExtendedPrivate.Error {
        switch error {
        case .depthOverflow:
            return .depthOverflow
        case .invalidSeed,
             .invalidKeyKind,
             .hardenedDerivationRequiresPrivateKey,
             .invalidDerivedKey:
            return .invalidDerivedKey
        }
    }
}
