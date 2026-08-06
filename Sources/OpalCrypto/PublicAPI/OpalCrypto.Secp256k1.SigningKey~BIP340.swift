// OpalCrypto.Secp256k1.SigningKey~BIP340.swift

extension OpalCrypto.Secp256k1.SigningKey {
    /// The BIP340 x-only verification key for this signing capability.
    public var bip340VerificationKey:
        OpalCrypto.Signature.BIP340.VerificationKey {
        let publicPoint = HardenedScalarMultiplicationModel.multiply(
            parsedPrivateKeyModel.scalar,
            by: ScalarMultiplicationModel.generator
        )
        guard let publicAffinePoint = publicPoint.affinePoint else {
            preconditionFailure(
                "A validated nonzero signing key must produce a public point."
            )
        }
        return OpalCrypto.Signature.BIP340.VerificationKey(
            verificationKeyModel:
                BitcoinImprovementProposal340VerificationKeyModel(
                    affinePoint: publicAffinePoint
                )
        )
    }

    /// Signs an existing 32-byte digest with BIP340 and explicit auxiliary randomness.
    ///
    /// The digest bytes are used as BIP340's message `m`. The operation does
    /// not apply a separate prehash. Auxiliary randomness has no default so
    /// the signing-time entropy decision remains explicit at every call site.
    public func signBIP340(
        digest: OpalCrypto.Signature.Digest,
        auxiliaryRandomness:
            OpalCrypto.Signature.BIP340.AuxiliaryRandomness
    ) throws -> OpalCrypto.Signature.BIP340 {
        do {
            let components = try
                BitcoinImprovementProposal340SignatureModel.sign(
                    digestData32Bytes: digest.rawRepresentation,
                    privateKeyScalar: parsedPrivateKeyModel.scalar,
                    auxiliaryRandomnessData32Bytes:
                        auxiliaryRandomness.rawRepresentation
                )
            return OpalCrypto.Signature.BIP340(
                rFieldElementModel: components.signatureRFieldElement,
                sScalarModel: components.signatureSScalar
            )
        } catch {
            throw OpalCrypto.Signature.BIP340.Error.signingFailed
        }
    }
}
