// OpalCryptoBenchmarks~SignatureBenchmarkFixtures.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func cpuSchnorrBatchFixture(
        count: Int
    ) throws -> SchnorrCPUVerificationBatchFixture {
        guard let fixture = schnorrDistinctBatchFixture.cpuBatches[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return fixture
    }

    static let schnorrDistinctBatchFixture = try! SchnorrDistinctBatchFixture()
    static let schnorrVaryingKeyBatchFixture = try! SchnorrVaryingKeyBatchFixture()
}
