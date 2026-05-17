// OpalCrypto.Pedersen+CommitmentPoint.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen {
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

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("commitment_parse"),
                OpalDiagnostics.Field.publicField("commitment_byte_count", rawRepresentation.count)
            ]
            do {
                affinePoint = try PublicKeyParserModel.parsePublicKey(rawRepresentation)
            } catch PublicKeyParserModel.Error.invalidLength(let actual) {
                let mappedError = Error.invalidCommitmentLength(actual: actual)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCommitmentParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitmentParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidCommitment
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCommitmentParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitmentParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
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
    }
}
