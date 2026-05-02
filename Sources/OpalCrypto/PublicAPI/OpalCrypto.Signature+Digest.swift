// OpalCrypto.Signature+Digest.swift

import Foundation

extension OpalCrypto.Signature {
    public struct Digest: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidDigestLength(expected: 32, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
