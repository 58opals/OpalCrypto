// OpalCrypto.Pedersen.Setup~Diagnostics.swift

import OpalDiagnostics

extension OpalCrypto.Pedersen.Setup {
    static func commitFields(nonce: OpalCrypto.Pedersen.Nonce?) -> [OpalDiagnostics.Field] {
        var fields = [
            OpalDiagnostics.Field.operationField("commit"),
            OpalDiagnostics.Field.publicField("has_provided_nonce", nonce != nil)
        ]
        if let nonce {
            fields.append(
                OpalDiagnostics.Field.publicField(
                    "nonce_byte_count",
                    nonce.rawRepresentation.count
                )
            )
        }
        return fields
    }

    static func recordCommitSucceeded(
        commitment: OpalCrypto.Pedersen.Commitment,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
            event: OpalDiagnostics.Event.pedersenCommitSucceeded,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitSucceeded),
            fields: fields + [
                OpalDiagnostics.Field.publicField(
                    "commitment_byte_count",
                    commitment.point.rawRepresentation.count
                )
            ]
        )
    }

    static func recordCommitFailed(
        _ error: Swift.Error,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
            event: OpalDiagnostics.Event.pedersenCommitFailed,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitFailed),
            fields: fields + OpalDiagnostics.Field.errorFields(error)
        )
    }

    static func recordCombineSucceeded(
        outputByteCount: Int,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
            event: OpalDiagnostics.Event.pedersenCombineSucceeded,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCombineSucceeded),
            fields: fields + [
                OpalDiagnostics.Field.publicField("commitment_byte_count", outputByteCount)
            ]
        )
    }

    static func recordCombineFailed(
        _ error: Swift.Error,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
            event: OpalDiagnostics.Event.pedersenCombineFailed,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCombineFailed),
            fields: fields + OpalDiagnostics.Field.errorFields(error)
        )
    }

    static func mapError(
        _ error: PedersenModel.Error
    ) -> OpalCrypto.Pedersen.Error {
        switch error {
        case .invalidAlternateBasePointLength(let actual):
            return .invalidAlternateBasePointLength(actual: actual)
        case .invalidAlternateBasePointPrefix(let actual):
            return .invalidAlternateBasePointPrefix(actual: actual)
        case .invalidAlternateBasePoint:
            return .invalidAlternateBasePoint
        case .insecureAlternateBasePoint:
            return .insecureAlternateBasePoint
        case .invalidNonceLength(let actual):
            return .invalidNonceLength(expected: 32, actual: actual)
        case .invalidNonce:
            return .invalidNonce
        case .invalidCommitmentLength(let actual):
            return .invalidCommitmentLength(actual: actual)
        case .invalidCommitment:
            return .invalidCommitment
        case .emptyCommitmentList:
            return .emptyCommitmentList
        case .mismatchedSetup:
            return .mismatchedSetup
        case .cryptographyFailure:
            return .cryptographyFailure
        }
    }
}
