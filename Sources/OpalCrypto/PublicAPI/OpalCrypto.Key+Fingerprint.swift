// OpalCrypto.Key+Fingerprint.swift

import Foundation

extension OpalCrypto.Key {
    public struct Fingerprint: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 4 else {
                throw ExtendedPrivate.Error.invalidParentFingerprintLength(
                    expected: 4,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
