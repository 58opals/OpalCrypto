// OpalCrypto.Pedersen+CommitmentPoint.swift

import Foundation

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
                OpalCryptoDiagnostics.operationField("commitment_parse"),
                OpalCryptoDiagnostics.publicField("commitment_byte_count", rawRepresentation.count)
            ]
            do {
                affinePoint = try PublicKeyParserModel.parsePublicKey(rawRepresentation)
            } catch PublicKeyParserModel.Error.invalidLength(let actual) {
                let mappedError = Error.invalidCommitmentLength(actual: actual)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCommitmentParseFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidCommitment
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCommitmentParseFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.pedersenCommitmentParseSucceeded,
                category: OpalCryptoDiagnostics.Category.pedersen,
                fields: fields
            )
        }

        internal init(affinePoint: AffinePointModel) {
            self.affinePoint = affinePoint
        }
    }
}
