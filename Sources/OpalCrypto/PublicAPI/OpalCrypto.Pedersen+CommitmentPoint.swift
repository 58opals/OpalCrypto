// OpalCrypto.Pedersen+CommitmentPoint.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen {
    /// A validated secp256k1 point used as a Pedersen commitment.
    public struct CommitmentPoint: Sendable, Equatable {
        internal let affinePoint: AffinePointModel

        public var rawRepresentation: Data {
            uncompressedRepresentation
        }

        public var compressedRepresentation: Data {
            affinePoint.encodeCompressed33()
        }

        public var uncompressedRepresentation: Data {
            affinePoint.encodeUncompressed65()
        }

        /// Parses a compressed or uncompressed SEC1 commitment point.
        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("commitment_parse"),
                OpalDiagnostics.Field.publicField("commitment_byte_count", rawRepresentation.count)
            ]
            do {
                affinePoint = try PublicKeyParserModel.parsePublicKey(rawRepresentation)
            } catch {
                let mappedError = Self.mapParseError(error)
                Self.recordParseFailed(mappedError, fields: fields)
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                event: OpalDiagnostics.Event.pedersenCommitmentParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitmentParseSucceeded),
                fields: fields
            )
        }

        internal init(affinePoint: AffinePointModel) {
            self.affinePoint = affinePoint
        }

        internal init(validatingRawRepresentation rawRepresentation: Data) throws {
            self.affinePoint = try PublicKeyParserModel.parsePublicKey(rawRepresentation)
        }

        private static func mapParseError(_ error: Swift.Error) -> Error {
            if case PublicKeyParserModel.Error.invalidLength(let actual) = error {
                return .invalidCommitmentLength(actual: actual)
            }
            return .invalidCommitment
        }

        private static func recordParseFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                event: OpalDiagnostics.Event.pedersenCommitmentParseFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitmentParseFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
