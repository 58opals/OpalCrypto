// OpalCrypto.RSABSSA+MessageRandomizer.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// The 32-byte randomized-message prefix required by the randomized variant.
    public struct MessageRandomizer: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let expected = Variant.sha384PSSRandomized.messageRandomizerByteCount
            guard rawRepresentation.count == expected else {
                throw Error.invalidMessageRandomizerLength(
                    expected: expected,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
