// InternalBase58CheckValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Internal Base58Check validation")
struct InternalBase58CheckValidator {
    @Test("Reject invalid minimum payload lengths without trapping")
    func rejectInvalidMinimumPayloadLengthsWithoutTrapping() {
        do {
            _ = try Base58CheckCodec.decode("", minimumPayloadLength: -4)
            Issue.record("Expected invalid payload length error.")
        } catch let error as Base58CheckCodec.Error {
            #expect(error == .invalidPayloadLength(actual: 0))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try Base58CheckCodec.decode("", minimumPayloadLength: Int.max)
            Issue.record("Expected invalid payload length error.")
        } catch let error as Base58CheckCodec.Error {
            #expect(error == .invalidPayloadLength(actual: 0))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
