// OpalCrypto.RSABSSA+BlindSignature.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// A fixed-width blind-signature response for the supported RSA-2048 contract.
    public struct BlindSignature: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let expected = Variant.sha384PSSRandomized.modulusByteCount
            guard rawRepresentation.count == expected else {
                throw Error.invalidBlindSignatureLength(
                    expected: expected,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
