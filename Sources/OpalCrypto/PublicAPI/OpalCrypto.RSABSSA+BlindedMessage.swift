// OpalCrypto.RSABSSA+BlindedMessage.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// A fixed-width blinded message for the currently supported RSA-2048 contract.
    public struct BlindedMessage: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let expected = Variant.sha384PSSRandomized.modulusByteCount
            guard rawRepresentation.count == expected else {
                throw Error.invalidBlindedMessageLength(
                    expected: expected,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
