// OpalCrypto.Communication+SymmetricKey.swift

import Foundation

extension OpalCrypto.Communication {
    public struct SymmetricKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidSymmetricKeyLength(expected: 32, actual: rawRepresentation.count)
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
