// OpalCrypto.Secp256k1~SharedPointDerivation.swift

import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// Derives the affine x-coordinate of `signingKey * publicKey`.
    ///
    /// This overload keeps the private scalar inside the opaque signing
    /// capability. The dedicated implementation uses a fixed 256-round
    /// schedule, exception-free complete point formulas, and mask-based
    /// scalar-bit selection.
    public static func deriveSharedPointXCoordinate(
        signingKey: SigningKey,
        publicKey: PublicKey
    ) -> SharedPointXCoordinate {
        deriveSharedPointXCoordinate(
            privateScalar: signingKey.parsedPrivateKeyModel.scalar,
            privateKeyByteCount: SigningKey.privateKeyByteCount,
            publicKey: publicKey
        )
    }

    /// Derives the affine x-coordinate of `privateKey * publicKey`.
    ///
    /// The dedicated implementation uses a fixed 256-round schedule,
    /// exception-free complete point formulas, and mask-based scalar-bit
    /// selection. It does not use the variable-time wNAF implementation that
    /// backs the legacy compressed-SEC1 shared-secret digest.
    public static func deriveSharedPointXCoordinate(
        privateKey: PrivateKey,
        publicKey: PublicKey
    ) -> SharedPointXCoordinate {
        deriveSharedPointXCoordinate(
            privateScalar: privateKey.scalarModel,
            privateKeyByteCount: privateKey.rawRepresentation.count,
            publicKey: publicKey
        )
    }

    private static func deriveSharedPointXCoordinate(
        privateScalar: ScalarModel,
        privateKeyByteCount: Int,
        publicKey: PublicKey
    ) -> SharedPointXCoordinate {
        let coordinate = SharedPointXCoordinate(
            validatedRawRepresentation:
                HardenedScalarMultiplicationModel
                    .deriveAffineXCoordinateData32Bytes(
                        scalar: privateScalar,
                        point: publicKey.parsedPublicKeyModel.affinePoint
                    )
        )
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
            event: OpalDiagnostics.Event.sharedPointXDeriveSucceeded,
            level: .opalCryptoDefault(
                for: OpalDiagnostics.Event.sharedPointXDeriveSucceeded
            ),
            fields: [
                OpalDiagnostics.Field.operationField("shared_point_x_derive"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.publicField(
                    "private_key_byte_count",
                    privateKeyByteCount
                ),
                OpalDiagnostics.Field.publicField(
                    "public_key_byte_count",
                    publicKey.rawRepresentation.count
                ),
                OpalDiagnostics.Field.outputLengthField(
                    coordinate.rawRepresentation.count
                )
            ]
        )
        return coordinate
    }
}
