// OpalCrypto.Signature+ECDSA.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Signature {
    public struct ECDSA: Sendable, Equatable {
        internal let signatureModel: StandardsForEfficientCryptography256k1CurveModel.Signature

        public let format: ECDSAFormat
        public let rawRepresentation: Data

        public init(
            rawRepresentation: Data,
            format: ECDSAFormat
        ) throws {
            self.format = format
            do {
                switch format {
                case .raw:
                    signatureModel = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                        raw64ByteSignatureData: rawRepresentation
                    )
                    self.rawRepresentation = Data(rawRepresentation)
                case .der:
                    signatureModel = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                        distinguishedEncodingRulesEncoded: rawRepresentation
                    )
                    self.rawRepresentation = Data(rawRepresentation)
                }
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
                throw Self.mapSignatureError(error, format: format)
            }
        }

        internal init(
            signatureModel: StandardsForEfficientCryptography256k1CurveModel.Signature,
            format: ECDSAFormat
        ) throws {
            self.signatureModel = signatureModel
            self.format = format
            switch format {
            case .raw:
                rawRepresentation = signatureModel.raw64ByteSignatureData
            case .der:
                rawRepresentation = try signatureModel.encodeDistinguishedEncodingRules()
            }
        }

        public func encoded(as format: ECDSAFormat) throws -> ECDSA {
            try ECDSA(signatureModel: signatureModel, format: format)
        }

        public func normalizedLowS() throws -> ECDSA {
            try ECDSA(
                signatureModel: signatureModel.normalizeLowS(),
                format: format
            )
        }

        public var isLowS: Bool {
            signatureModel.isLowS
        }

        private static func mapSignatureError(
            _ error: StandardsForEfficientCryptography256k1CurveModel.Error,
            format: ECDSAFormat
        ) -> Error {
            switch error {
            case .invalidSignatureLength(let actual):
                return .invalidSignatureLength(
                    expected: format == .raw ? 64 : actual,
                    actual: actual
                )
            case .signatureComponentZero, .invalidSignatureScalar:
                return .invalidSignature
            case .derMalformed:
                return .invalidDER
            case .derNonCanonical:
                return .nonCanonicalDER
            case .invalidDigestLength,
                 .invalidPrivateKeyLength,
                 .invalidPrivateKeyValue,
                 .invalidPublicKeyLength,
                 .randomGenerationFailed:
                return .cryptographyFailure
            }
        }
    }
}
