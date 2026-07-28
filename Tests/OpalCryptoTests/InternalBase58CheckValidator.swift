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
            _ = try Base58CheckCodec.decode(
                "",
                minimumPayloadLength: minimumPayloadLength,
                maximumPayloadLength: 0
            )
        }
    }

    @Test("Reject oversized payloads without inventing an actual length")
    func rejectOversizedPayloadsWithoutInventingAnActualLength() {
        #expect(
            throws: Base58CheckCodec.Error
                .payloadLengthExceedsMaximum(maximum: 1)
        ) {
            _ = try Base58CheckCodec.decode(
                "111111",
                maximumPayloadLength: 1
            )
        }
    }
}
