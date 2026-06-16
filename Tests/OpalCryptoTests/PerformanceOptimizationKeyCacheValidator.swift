// PerformanceOptimizationKeyCacheValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Performance optimization key-cache validation")
struct PerformanceOptimizationKeyCacheValidator {
    func expectTrustedPayloadMatchesValidatedPayload(
        _ trustedPayload: ExtendedKeyPayloadModel,
        validatedPayload: ExtendedKeyPayloadModel
    ) {
        #expect(trustedPayload == validatedPayload)
        #expect(trustedPayload.serialize() == validatedPayload.serialize())
    }
}
