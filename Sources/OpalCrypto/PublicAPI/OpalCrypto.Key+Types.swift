// OpalCrypto.Key+Types.swift

import Foundation

extension OpalCrypto.Key {
    public struct Seed: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard (16...64).contains(rawRepresentation.count) else {
                throw ExtendedPrivate.Error.invalidSeedLength(actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }
    }

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
