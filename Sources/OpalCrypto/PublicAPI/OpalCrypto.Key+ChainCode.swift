// OpalCrypto.Key+ChainCode.swift

import Foundation

extension OpalCrypto.Key {
    public struct ChainCode: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw ExtendedPrivate.Error.invalidChainCodeLength(
                    expected: 32,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
