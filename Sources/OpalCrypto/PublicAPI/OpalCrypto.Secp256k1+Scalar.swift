// OpalCrypto.Secp256k1+Scalar.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public struct Scalar: Sendable, Equatable {
        internal let scalarModel: ScalarModel

        public var rawRepresentation: Data {
            scalarModel.data32Bytes
        }

        public init(rawRepresentation: Data) throws {
            do {
                scalarModel = try ScalarModel(data32: rawRepresentation, requireNonZero: false)
            } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                precondition(expected == 32)
                throw Error.invalidTweakLength(expected: expected, actual: actual)
            } catch {
                throw Error.invalidTweak
            }
        }

        internal init(scalarModel: ScalarModel) {
            self.scalarModel = scalarModel
        }
    }
}
