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
            do {
                affinePoint = try PublicKeyParserModel.parsePublicKey(rawRepresentation)
            } catch PublicKeyParserModel.Error.invalidLength(let actual) {
                throw Error.invalidCommitmentLength(actual: actual)
            } catch {
                throw Error.invalidCommitment
            }
        }

        internal init(affinePoint: AffinePointModel) {
            self.affinePoint = affinePoint
        }
    }
}
