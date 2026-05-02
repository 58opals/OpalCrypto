// OpalCrypto.Pedersen+Types.swift

import Foundation

extension OpalCrypto.Pedersen {
    public struct Nonce: Sendable, Equatable {
        internal let scalarModel: ScalarModel

        public var rawRepresentation: Data {
            scalarModel.data32Bytes
        }

        public init(rawRepresentation: Data) throws {
            do {
                scalarModel = try ScalarModel(data32: rawRepresentation, requireNonZero: false)
            } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                precondition(expected == 32)
                throw Error.invalidNonceLength(expected: expected, actual: actual)
            } catch {
                throw Error.invalidNonce
            }
        }

        internal init(scalarModel: ScalarModel) {
            self.scalarModel = scalarModel
        }
    }

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
