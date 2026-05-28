// InternalBase58CheckValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Internal Base58Check validation")
struct InternalBase58CheckValidator {
    @Test(
        "Reject invalid minimum payload lengths without trapping",
        arguments: [-4, Int.max]
    )
    func validateBase58CheckRejectsInvalidMinimumPayloadLengthsWithoutTrapping(
        minimumPayloadLength: Int
    ) {
        #expect(throws: Base58CheckCodec.Error.invalidPayloadLength(actual: 0)) {
            _ = try Base58CheckCodec.decode("", minimumPayloadLength: minimumPayloadLength)
        }
    }
}
