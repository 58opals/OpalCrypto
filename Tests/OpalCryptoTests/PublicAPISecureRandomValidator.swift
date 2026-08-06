// PublicAPISecureRandomValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API secure random byte validation")
struct PublicAPISecureRandomValidator {
    @Test("Make secure random bytes within the allocation-safety boundary")
    func makeSecureRandomBytesWithinAllocationSafetyBoundary() throws {
        for count in [1, 32, 1024] {
            #expect(try OpalCrypto.SecureRandom.makeBytes(count: count).count == count)
        }
    }

    @Test("Reject secure random byte counts outside the allocation-safety boundary")
    func rejectSecureRandomByteCountsOutsideAllocationSafetyBoundary() {
        for count in [-1, 0, 1025, Int.max] {
            do {
                _ = try OpalCrypto.SecureRandom.makeBytes(count: count)
                Issue.record("Expected byte-count rejection for \(count).")
            } catch let error as OpalCrypto.SecureRandom.Error {
                #expect(
                    error == .invalidByteCount(
                        minimum: 1,
                        maximum: 1024,
                        actual: count
                    )
                )
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }
}
