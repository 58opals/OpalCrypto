// OpalCrypto.RSABSSA+Signature.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// A fixed-width finalized signature for the supported RSA-2048 contract.
    public struct Signature: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let expected = Variant.sha384PSSRandomized.modulusByteCount
            guard rawRepresentation.count == expected else {
                throw Error.invalidSignatureLength(
                    expected: expected,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
