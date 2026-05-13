// OpalCrypto.Secp256k1+PrivateKey.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public struct PrivateKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            try OpalCrypto.Secp256k1.validatePrivateKey(rawRepresentation)
            self.rawRepresentation = Data(rawRepresentation)
        }

        public static func generate() throws -> PrivateKey {
            do {
                return try PrivateKey(
                    rawRepresentation: StandardsForEfficientCryptography256k1CurveModel.Operation
                        .generatePrivateKeyData32Bytes()
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw OpalCrypto.Secp256k1.mapOperationError(error)
            }
        }
    }
}
