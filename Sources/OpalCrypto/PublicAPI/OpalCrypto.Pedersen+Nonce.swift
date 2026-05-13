// OpalCrypto.Pedersen+Nonce.swift

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
}
